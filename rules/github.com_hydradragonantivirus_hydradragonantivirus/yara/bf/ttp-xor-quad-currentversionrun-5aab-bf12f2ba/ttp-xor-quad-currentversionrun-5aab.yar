rule TTP_XOR_QUAD_CurrentVersionRun_5aab {
  strings:
    $key_5aab = { 09 c4 [2] 2d ca [2] 06 e6 [2] 28 c4 [2] 3c df [2] 33 c5 [2] 2d d8 [2] 2f d9 [2] 34 df [2] 28 d8 [2] 34 f7 }

  condition:
    any of them
}