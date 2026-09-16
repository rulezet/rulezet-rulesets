rule TTP_XOR_QUAD_CurrentVersionRun_5652 {
  strings:
    $key_5652 = { 05 3d [2] 21 33 [2] 0a 1f [2] 24 3d [2] 30 26 [2] 3f 3c [2] 21 21 [2] 23 20 [2] 38 26 [2] 24 21 [2] 38 0e }

  condition:
    any of them
}