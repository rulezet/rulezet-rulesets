rule TTP_XOR_QUAD_CurrentVersionRun_2d52 {
  strings:
    $key_2d52 = { 7e 3d [2] 5a 33 [2] 71 1f [2] 5f 3d [2] 4b 26 [2] 44 3c [2] 5a 21 [2] 58 20 [2] 43 26 [2] 5f 21 [2] 43 0e }

  condition:
    any of them
}