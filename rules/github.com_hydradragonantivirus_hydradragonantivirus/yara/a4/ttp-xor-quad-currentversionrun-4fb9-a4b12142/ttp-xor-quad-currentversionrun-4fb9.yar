rule TTP_XOR_QUAD_CurrentVersionRun_4fb9 {
  strings:
    $key_4fb9 = { 1c d6 [2] 38 d8 [2] 13 f4 [2] 3d d6 [2] 29 cd [2] 26 d7 [2] 38 ca [2] 3a cb [2] 21 cd [2] 3d ca [2] 21 e5 }

  condition:
    any of them
}