rule TTP_XOR_QUAD_CurrentVersionRun_74ab {
  strings:
    $key_74ab = { 27 c4 [2] 03 ca [2] 28 e6 [2] 06 c4 [2] 12 df [2] 1d c5 [2] 03 d8 [2] 01 d9 [2] 1a df [2] 06 d8 [2] 1a f7 }

  condition:
    any of them
}