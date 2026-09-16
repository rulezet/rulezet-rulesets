rule TTP_XOR_QUAD_CurrentVersionRun_04f3 {
  strings:
    $key_04f3 = { 57 9c [2] 73 92 [2] 58 be [2] 76 9c [2] 62 87 [2] 6d 9d [2] 73 80 [2] 71 81 [2] 6a 87 [2] 76 80 [2] 6a af }

  condition:
    any of them
}