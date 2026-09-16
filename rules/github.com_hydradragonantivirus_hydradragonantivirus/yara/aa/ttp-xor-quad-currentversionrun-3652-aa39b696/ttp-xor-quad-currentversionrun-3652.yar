rule TTP_XOR_QUAD_CurrentVersionRun_3652 {
  strings:
    $key_3652 = { 65 3d [2] 41 33 [2] 6a 1f [2] 44 3d [2] 50 26 [2] 5f 3c [2] 41 21 [2] 43 20 [2] 58 26 [2] 44 21 [2] 58 0e }

  condition:
    any of them
}