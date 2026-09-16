rule TTP_XOR_QUAD_CurrentVersionRun_54f3 {
  strings:
    $key_54f3 = { 07 9c [2] 23 92 [2] 08 be [2] 26 9c [2] 32 87 [2] 3d 9d [2] 23 80 [2] 21 81 [2] 3a 87 [2] 26 80 [2] 3a af }

  condition:
    any of them
}