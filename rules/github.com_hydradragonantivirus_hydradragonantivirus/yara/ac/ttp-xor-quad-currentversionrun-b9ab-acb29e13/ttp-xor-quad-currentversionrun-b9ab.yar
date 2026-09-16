rule TTP_XOR_QUAD_CurrentVersionRun_b9ab {
  strings:
    $key_b9ab = { ea c4 [2] ce ca [2] e5 e6 [2] cb c4 [2] df df [2] d0 c5 [2] ce d8 [2] cc d9 [2] d7 df [2] cb d8 [2] d7 f7 }

  condition:
    any of them
}