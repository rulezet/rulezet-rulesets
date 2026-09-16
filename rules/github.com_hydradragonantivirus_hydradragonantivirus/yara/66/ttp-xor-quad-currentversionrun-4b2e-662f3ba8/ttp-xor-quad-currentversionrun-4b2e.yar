rule TTP_XOR_QUAD_CurrentVersionRun_4b2e {
  strings:
    $key_4b2e = { 18 41 [2] 3c 4f [2] 17 63 [2] 39 41 [2] 2d 5a [2] 22 40 [2] 3c 5d [2] 3e 5c [2] 25 5a [2] 39 5d [2] 25 72 }

  condition:
    any of them
}