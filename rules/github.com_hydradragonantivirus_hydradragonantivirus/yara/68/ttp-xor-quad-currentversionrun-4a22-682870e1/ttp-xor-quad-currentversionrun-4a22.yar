rule TTP_XOR_QUAD_CurrentVersionRun_4a22 {
  strings:
    $key_4a22 = { 19 4d [2] 3d 43 [2] 16 6f [2] 38 4d [2] 2c 56 [2] 23 4c [2] 3d 51 [2] 3f 50 [2] 24 56 [2] 38 51 [2] 24 7e }

  condition:
    any of them
}