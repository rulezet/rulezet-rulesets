rule TTP_XOR_QUAD_CurrentVersionRun_51ab {
  strings:
    $key_51ab = { 02 c4 [2] 26 ca [2] 0d e6 [2] 23 c4 [2] 37 df [2] 38 c5 [2] 26 d8 [2] 24 d9 [2] 3f df [2] 23 d8 [2] 3f f7 }

  condition:
    any of them
}