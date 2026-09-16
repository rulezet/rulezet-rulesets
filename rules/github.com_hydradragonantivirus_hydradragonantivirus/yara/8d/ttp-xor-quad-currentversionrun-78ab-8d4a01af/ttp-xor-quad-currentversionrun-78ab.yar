rule TTP_XOR_QUAD_CurrentVersionRun_78ab {
  strings:
    $key_78ab = { 2b c4 [2] 0f ca [2] 24 e6 [2] 0a c4 [2] 1e df [2] 11 c5 [2] 0f d8 [2] 0d d9 [2] 16 df [2] 0a d8 [2] 16 f7 }

  condition:
    any of them
}