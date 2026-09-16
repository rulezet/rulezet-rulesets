rule TTP_XOR_QUAD_CurrentVersionRun_36ab {
  strings:
    $key_36ab = { 65 c4 [2] 41 ca [2] 6a e6 [2] 44 c4 [2] 50 df [2] 5f c5 [2] 41 d8 [2] 43 d9 [2] 58 df [2] 44 d8 [2] 58 f7 }

  condition:
    any of them
}