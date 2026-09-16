rule TTP_XOR_QUAD_CurrentVersionRun_f2ab {
  strings:
    $key_f2ab = { a1 c4 [2] 85 ca [2] ae e6 [2] 80 c4 [2] 94 df [2] 9b c5 [2] 85 d8 [2] 87 d9 [2] 9c df [2] 80 d8 [2] 9c f7 }

  condition:
    any of them
}