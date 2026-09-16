rule TTP_XOR_QUAD_CurrentVersionRun_7fb9 {
  strings:
    $key_7fb9 = { 2c d6 [2] 08 d8 [2] 23 f4 [2] 0d d6 [2] 19 cd [2] 16 d7 [2] 08 ca [2] 0a cb [2] 11 cd [2] 0d ca [2] 11 e5 }

  condition:
    any of them
}