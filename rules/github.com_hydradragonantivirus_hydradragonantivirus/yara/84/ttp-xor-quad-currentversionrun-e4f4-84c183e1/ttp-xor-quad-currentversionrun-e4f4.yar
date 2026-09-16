rule TTP_XOR_QUAD_CurrentVersionRun_e4f4 {
  strings:
    $key_e4f4 = { b7 9b [2] 93 95 [2] b8 b9 [2] 96 9b [2] 82 80 [2] 8d 9a [2] 93 87 [2] 91 86 [2] 8a 80 [2] 96 87 [2] 8a a8 }

  condition:
    any of them
}