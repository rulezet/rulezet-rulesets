rule TTP_XOR_QUAD_CurrentVersionRun_4eb9 {
  strings:
    $key_4eb9 = { 1d d6 [2] 39 d8 [2] 12 f4 [2] 3c d6 [2] 28 cd [2] 27 d7 [2] 39 ca [2] 3b cb [2] 20 cd [2] 3c ca [2] 20 e5 }

  condition:
    any of them
}