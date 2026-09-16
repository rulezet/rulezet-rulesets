rule TTP_XOR_QUAD_CurrentVersionRun_d9f4 {
  strings:
    $key_d9f4 = { 8a 9b [2] ae 95 [2] 85 b9 [2] ab 9b [2] bf 80 [2] b0 9a [2] ae 87 [2] ac 86 [2] b7 80 [2] ab 87 [2] b7 a8 }

  condition:
    any of them
}