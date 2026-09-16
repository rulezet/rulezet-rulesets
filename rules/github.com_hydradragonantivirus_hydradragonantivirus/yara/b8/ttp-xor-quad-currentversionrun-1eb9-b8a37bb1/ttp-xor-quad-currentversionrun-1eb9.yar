rule TTP_XOR_QUAD_CurrentVersionRun_1eb9 {
  strings:
    $key_1eb9 = { 4d d6 [2] 69 d8 [2] 42 f4 [2] 6c d6 [2] 78 cd [2] 77 d7 [2] 69 ca [2] 6b cb [2] 70 cd [2] 6c ca [2] 70 e5 }

  condition:
    any of them
}