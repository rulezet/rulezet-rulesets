rule TTP_XOR_QUAD_CurrentVersionRun_09ab {
  strings:
    $key_09ab = { 5a c4 [2] 7e ca [2] 55 e6 [2] 7b c4 [2] 6f df [2] 60 c5 [2] 7e d8 [2] 7c d9 [2] 67 df [2] 7b d8 [2] 67 f7 }

  condition:
    any of them
}