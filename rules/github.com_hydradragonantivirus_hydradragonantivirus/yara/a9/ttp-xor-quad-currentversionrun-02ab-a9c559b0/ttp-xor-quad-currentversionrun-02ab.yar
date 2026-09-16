rule TTP_XOR_QUAD_CurrentVersionRun_02ab {
  strings:
    $key_02ab = { 51 c4 [2] 75 ca [2] 5e e6 [2] 70 c4 [2] 64 df [2] 6b c5 [2] 75 d8 [2] 77 d9 [2] 6c df [2] 70 d8 [2] 6c f7 }

  condition:
    any of them
}