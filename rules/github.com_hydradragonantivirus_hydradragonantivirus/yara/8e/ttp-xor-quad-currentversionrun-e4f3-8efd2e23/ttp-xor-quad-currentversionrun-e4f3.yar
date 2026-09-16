rule TTP_XOR_QUAD_CurrentVersionRun_e4f3 {
  strings:
    $key_e4f3 = { b7 9c [2] 93 92 [2] b8 be [2] 96 9c [2] 82 87 [2] 8d 9d [2] 93 80 [2] 91 81 [2] 8a 87 [2] 96 80 [2] 8a af }

  condition:
    any of them
}