rule TTP_XOR_QUAD_CurrentVersionRun_292e {
  strings:
    $key_292e = { 7a 41 [2] 5e 4f [2] 75 63 [2] 5b 41 [2] 4f 5a [2] 40 40 [2] 5e 5d [2] 5c 5c [2] 47 5a [2] 5b 5d [2] 47 72 }

  condition:
    any of them
}