rule TTP_XOR_QUAD_CurrentVersionRun_66ab {
  strings:
    $key_66ab = { 35 c4 [2] 11 ca [2] 3a e6 [2] 14 c4 [2] 00 df [2] 0f c5 [2] 11 d8 [2] 13 d9 [2] 08 df [2] 14 d8 [2] 08 f7 }

  condition:
    any of them
}