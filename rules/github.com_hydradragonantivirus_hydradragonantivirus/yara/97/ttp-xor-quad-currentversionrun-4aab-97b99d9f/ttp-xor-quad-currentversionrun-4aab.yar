rule TTP_XOR_QUAD_CurrentVersionRun_4aab {
  strings:
    $key_4aab = { 19 c4 [2] 3d ca [2] 16 e6 [2] 38 c4 [2] 2c df [2] 23 c5 [2] 3d d8 [2] 3f d9 [2] 24 df [2] 38 d8 [2] 24 f7 }

  condition:
    any of them
}