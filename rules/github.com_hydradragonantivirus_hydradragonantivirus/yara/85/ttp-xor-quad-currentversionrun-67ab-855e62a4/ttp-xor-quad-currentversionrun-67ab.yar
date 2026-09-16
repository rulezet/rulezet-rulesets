rule TTP_XOR_QUAD_CurrentVersionRun_67ab {
  strings:
    $key_67ab = { 34 c4 [2] 10 ca [2] 3b e6 [2] 15 c4 [2] 01 df [2] 0e c5 [2] 10 d8 [2] 12 d9 [2] 09 df [2] 15 d8 [2] 09 f7 }

  condition:
    any of them
}