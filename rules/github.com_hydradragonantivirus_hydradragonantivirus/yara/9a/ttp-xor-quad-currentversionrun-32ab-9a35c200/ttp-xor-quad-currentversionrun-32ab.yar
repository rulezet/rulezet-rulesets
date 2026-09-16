rule TTP_XOR_QUAD_CurrentVersionRun_32ab {
  strings:
    $key_32ab = { 61 c4 [2] 45 ca [2] 6e e6 [2] 40 c4 [2] 54 df [2] 5b c5 [2] 45 d8 [2] 47 d9 [2] 5c df [2] 40 d8 [2] 5c f7 }

  condition:
    any of them
}