rule TTP_XOR_QUAD_CurrentVersionRun_13ab {
  strings:
    $key_13ab = { 40 c4 [2] 64 ca [2] 4f e6 [2] 61 c4 [2] 75 df [2] 7a c5 [2] 64 d8 [2] 66 d9 [2] 7d df [2] 61 d8 [2] 7d f7 }

  condition:
    any of them
}