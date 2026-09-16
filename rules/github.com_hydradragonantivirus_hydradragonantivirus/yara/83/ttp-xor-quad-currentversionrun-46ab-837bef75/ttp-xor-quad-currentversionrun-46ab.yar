rule TTP_XOR_QUAD_CurrentVersionRun_46ab {
  strings:
    $key_46ab = { 15 c4 [2] 31 ca [2] 1a e6 [2] 34 c4 [2] 20 df [2] 2f c5 [2] 31 d8 [2] 33 d9 [2] 28 df [2] 34 d8 [2] 28 f7 }

  condition:
    any of them
}