rule TTP_XOR_QUAD_CurrentVersionRun_084e {
  strings:
    $key_084e = { 5b 21 [2] 7f 2f [2] 54 03 [2] 7a 21 [2] 6e 3a [2] 61 20 [2] 7f 3d [2] 7d 3c [2] 66 3a [2] 7a 3d [2] 66 12 }

  condition:
    any of them
}