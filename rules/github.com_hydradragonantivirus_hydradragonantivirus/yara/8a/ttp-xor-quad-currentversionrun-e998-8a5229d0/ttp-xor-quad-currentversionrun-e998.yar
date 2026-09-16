rule TTP_XOR_QUAD_CurrentVersionRun_e998 {
  strings:
    $key_e998 = { ba f7 [2] 9e f9 [2] b5 d5 [2] 9b f7 [2] 8f ec [2] 80 f6 [2] 9e eb [2] 9c ea [2] 87 ec [2] 9b eb [2] 87 c4 }

  condition:
    any of them
}