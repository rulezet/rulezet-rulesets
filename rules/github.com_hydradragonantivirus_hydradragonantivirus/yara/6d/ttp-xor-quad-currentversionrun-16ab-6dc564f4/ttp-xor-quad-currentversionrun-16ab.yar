rule TTP_XOR_QUAD_CurrentVersionRun_16ab {
  strings:
    $key_16ab = { 45 c4 [2] 61 ca [2] 4a e6 [2] 64 c4 [2] 70 df [2] 7f c5 [2] 61 d8 [2] 63 d9 [2] 78 df [2] 64 d8 [2] 78 f7 }

  condition:
    any of them
}