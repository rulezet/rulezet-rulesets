rule TTP_XOR_QUAD_CurrentVersionRun_6eb9 {
  strings:
    $key_6eb9 = { 3d d6 [2] 19 d8 [2] 32 f4 [2] 1c d6 [2] 08 cd [2] 07 d7 [2] 19 ca [2] 1b cb [2] 00 cd [2] 1c ca [2] 00 e5 }

  condition:
    any of them
}