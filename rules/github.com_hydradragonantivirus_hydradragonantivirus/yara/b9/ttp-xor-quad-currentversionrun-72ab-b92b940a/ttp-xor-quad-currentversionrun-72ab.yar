rule TTP_XOR_QUAD_CurrentVersionRun_72ab {
  strings:
    $key_72ab = { 21 c4 [2] 05 ca [2] 2e e6 [2] 00 c4 [2] 14 df [2] 1b c5 [2] 05 d8 [2] 07 d9 [2] 1c df [2] 00 d8 [2] 1c f7 }

  condition:
    any of them
}