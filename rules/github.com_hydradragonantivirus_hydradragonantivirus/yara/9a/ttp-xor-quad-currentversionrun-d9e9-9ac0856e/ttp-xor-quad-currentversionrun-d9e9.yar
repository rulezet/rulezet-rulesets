rule TTP_XOR_QUAD_CurrentVersionRun_d9e9 {
  strings:
    $key_d9e9 = { 8a 86 [2] ae 88 [2] 85 a4 [2] ab 86 [2] bf 9d [2] b0 87 [2] ae 9a [2] ac 9b [2] b7 9d [2] ab 9a [2] b7 b5 }

  condition:
    any of them
}