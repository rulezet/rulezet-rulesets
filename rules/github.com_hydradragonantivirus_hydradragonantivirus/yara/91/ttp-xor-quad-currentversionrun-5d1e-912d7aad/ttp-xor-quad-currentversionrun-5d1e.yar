rule TTP_XOR_QUAD_CurrentVersionRun_5d1e {
  strings:
    $key_5d1e = { 0e 71 [2] 2a 7f [2] 01 53 [2] 2f 71 [2] 3b 6a [2] 34 70 [2] 2a 6d [2] 28 6c [2] 33 6a [2] 2f 6d [2] 33 42 }

  condition:
    any of them
}