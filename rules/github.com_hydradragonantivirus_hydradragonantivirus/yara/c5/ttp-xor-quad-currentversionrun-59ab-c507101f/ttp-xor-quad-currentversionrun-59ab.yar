rule TTP_XOR_QUAD_CurrentVersionRun_59ab {
  strings:
    $key_59ab = { 0a c4 [2] 2e ca [2] 05 e6 [2] 2b c4 [2] 3f df [2] 30 c5 [2] 2e d8 [2] 2c d9 [2] 37 df [2] 2b d8 [2] 37 f7 }

  condition:
    any of them
}