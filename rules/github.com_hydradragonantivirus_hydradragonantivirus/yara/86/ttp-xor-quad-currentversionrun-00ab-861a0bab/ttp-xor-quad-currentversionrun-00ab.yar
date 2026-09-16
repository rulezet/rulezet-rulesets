rule TTP_XOR_QUAD_CurrentVersionRun_00ab {
  strings:
    $key_00ab = { 53 c4 [2] 77 ca [2] 5c e6 [2] 72 c4 [2] 66 df [2] 69 c5 [2] 77 d8 [2] 75 d9 [2] 6e df [2] 72 d8 [2] 6e f7 }

  condition:
    any of them
}