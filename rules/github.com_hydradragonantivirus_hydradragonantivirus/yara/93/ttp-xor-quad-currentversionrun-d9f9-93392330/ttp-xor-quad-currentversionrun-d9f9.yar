rule TTP_XOR_QUAD_CurrentVersionRun_d9f9 {
  strings:
    $key_d9f9 = { 8a 96 [2] ae 98 [2] 85 b4 [2] ab 96 [2] bf 8d [2] b0 97 [2] ae 8a [2] ac 8b [2] b7 8d [2] ab 8a [2] b7 a5 }

  condition:
    any of them
}