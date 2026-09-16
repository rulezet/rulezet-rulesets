rule TTP_XOR_QUAD_CurrentVersionRun_7aab {
  strings:
    $key_7aab = { 29 c4 [2] 0d ca [2] 26 e6 [2] 08 c4 [2] 1c df [2] 13 c5 [2] 0d d8 [2] 0f d9 [2] 14 df [2] 08 d8 [2] 14 f7 }

  condition:
    any of them
}