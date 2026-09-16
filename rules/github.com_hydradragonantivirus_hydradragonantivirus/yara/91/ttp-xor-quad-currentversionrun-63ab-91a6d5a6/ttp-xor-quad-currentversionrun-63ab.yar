rule TTP_XOR_QUAD_CurrentVersionRun_63ab {
  strings:
    $key_63ab = { 30 c4 [2] 14 ca [2] 3f e6 [2] 11 c4 [2] 05 df [2] 0a c5 [2] 14 d8 [2] 16 d9 [2] 0d df [2] 11 d8 [2] 0d f7 }

  condition:
    any of them
}