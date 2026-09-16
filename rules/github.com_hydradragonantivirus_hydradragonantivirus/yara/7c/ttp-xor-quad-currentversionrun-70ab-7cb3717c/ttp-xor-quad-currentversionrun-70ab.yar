rule TTP_XOR_QUAD_CurrentVersionRun_70ab {
  strings:
    $key_70ab = { 23 c4 [2] 07 ca [2] 2c e6 [2] 02 c4 [2] 16 df [2] 19 c5 [2] 07 d8 [2] 05 d9 [2] 1e df [2] 02 d8 [2] 1e f7 }

  condition:
    any of them
}