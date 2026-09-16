rule TTP_XOR_QUAD_CurrentVersionRun_cfb9 {
  strings:
    $key_cfb9 = { 9c d6 [2] b8 d8 [2] 93 f4 [2] bd d6 [2] a9 cd [2] a6 d7 [2] b8 ca [2] ba cb [2] a1 cd [2] bd ca [2] a1 e5 }

  condition:
    any of them
}