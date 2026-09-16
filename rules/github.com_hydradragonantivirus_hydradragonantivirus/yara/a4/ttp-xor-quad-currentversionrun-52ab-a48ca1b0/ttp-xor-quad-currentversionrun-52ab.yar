rule TTP_XOR_QUAD_CurrentVersionRun_52ab {
  strings:
    $key_52ab = { 01 c4 [2] 25 ca [2] 0e e6 [2] 20 c4 [2] 34 df [2] 3b c5 [2] 25 d8 [2] 27 d9 [2] 3c df [2] 20 d8 [2] 3c f7 }

  condition:
    any of them
}