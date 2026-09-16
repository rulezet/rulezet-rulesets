rule TTP_XOR_QUAD_CurrentVersionRun_64f3 {
  strings:
    $key_64f3 = { 37 9c [2] 13 92 [2] 38 be [2] 16 9c [2] 02 87 [2] 0d 9d [2] 13 80 [2] 11 81 [2] 0a 87 [2] 16 80 [2] 0a af }

  condition:
    any of them
}