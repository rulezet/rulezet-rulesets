rule TTP_XOR_QUAD_CurrentVersionRun_5fb9 {
  strings:
    $key_5fb9 = { 0c d6 [2] 28 d8 [2] 03 f4 [2] 2d d6 [2] 39 cd [2] 36 d7 [2] 28 ca [2] 2a cb [2] 31 cd [2] 2d ca [2] 31 e5 }

  condition:
    any of them
}