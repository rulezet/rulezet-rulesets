rule TTP_XOR_QUAD_CurrentVersionRun_d9e8 {
  strings:
    $key_d9e8 = { 8a 87 [2] ae 89 [2] 85 a5 [2] ab 87 [2] bf 9c [2] b0 86 [2] ae 9b [2] ac 9a [2] b7 9c [2] ab 9b [2] b7 b4 }

  condition:
    any of them
}