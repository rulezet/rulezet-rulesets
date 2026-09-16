rule TTP_XOR_QUAD_CurrentVersionRun_faab {
  strings:
    $key_faab = { a9 c4 [2] 8d ca [2] a6 e6 [2] 88 c4 [2] 9c df [2] 93 c5 [2] 8d d8 [2] 8f d9 [2] 94 df [2] 88 d8 [2] 94 f7 }

  condition:
    any of them
}