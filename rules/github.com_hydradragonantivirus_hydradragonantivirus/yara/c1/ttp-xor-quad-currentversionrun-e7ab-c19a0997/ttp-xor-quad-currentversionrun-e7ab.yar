rule TTP_XOR_QUAD_CurrentVersionRun_e7ab {
  strings:
    $key_e7ab = { b4 c4 [2] 90 ca [2] bb e6 [2] 95 c4 [2] 81 df [2] 8e c5 [2] 90 d8 [2] 92 d9 [2] 89 df [2] 95 d8 [2] 89 f7 }

  condition:
    any of them
}