rule TTP_XOR_QUAD_CurrentVersionRun_5af7 {
  strings:
    $key_5af7 = { 09 98 [2] 2d 96 [2] 06 ba [2] 28 98 [2] 3c 83 [2] 33 99 [2] 2d 84 [2] 2f 85 [2] 34 83 [2] 28 84 [2] 34 ab }

  condition:
    any of them
}