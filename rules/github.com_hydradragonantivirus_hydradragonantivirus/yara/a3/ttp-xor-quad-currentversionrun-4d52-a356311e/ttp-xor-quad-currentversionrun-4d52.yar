rule TTP_XOR_QUAD_CurrentVersionRun_4d52 {
  strings:
    $key_4d52 = { 1e 3d [2] 3a 33 [2] 11 1f [2] 3f 3d [2] 2b 26 [2] 24 3c [2] 3a 21 [2] 38 20 [2] 23 26 [2] 3f 21 [2] 23 0e }

  condition:
    any of them
}