rule TTP_XOR_QUAD_CurrentVersionRun_42ab {
  strings:
    $key_42ab = { 11 c4 [2] 35 ca [2] 1e e6 [2] 30 c4 [2] 24 df [2] 2b c5 [2] 35 d8 [2] 37 d9 [2] 2c df [2] 30 d8 [2] 2c f7 }

  condition:
    any of them
}