rule TTP_XOR_QUAD_CurrentVersionRun_03ab {
  strings:
    $key_03ab = { 50 c4 [2] 74 ca [2] 5f e6 [2] 71 c4 [2] 65 df [2] 6a c5 [2] 74 d8 [2] 76 d9 [2] 6d df [2] 71 d8 [2] 6d f7 }

  condition:
    any of them
}