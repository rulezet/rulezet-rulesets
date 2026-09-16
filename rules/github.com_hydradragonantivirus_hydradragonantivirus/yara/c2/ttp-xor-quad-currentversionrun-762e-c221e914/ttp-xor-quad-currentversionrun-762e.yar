rule TTP_XOR_QUAD_CurrentVersionRun_762e {
  strings:
    $key_762e = { 25 41 [2] 01 4f [2] 2a 63 [2] 04 41 [2] 10 5a [2] 1f 40 [2] 01 5d [2] 03 5c [2] 18 5a [2] 04 5d [2] 18 72 }

  condition:
    any of them
}