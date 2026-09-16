rule TTP_XOR_QUAD_CurrentVersionRun_76ab {
  strings:
    $key_76ab = { 25 c4 [2] 01 ca [2] 2a e6 [2] 04 c4 [2] 10 df [2] 1f c5 [2] 01 d8 [2] 03 d9 [2] 18 df [2] 04 d8 [2] 18 f7 }

  condition:
    any of them
}