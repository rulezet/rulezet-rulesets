rule TTP_XOR_QUAD_CurrentVersionRun_5998 {
  strings:
    $key_5998 = { 0a f7 [2] 2e f9 [2] 05 d5 [2] 2b f7 [2] 3f ec [2] 30 f6 [2] 2e eb [2] 2c ea [2] 37 ec [2] 2b eb [2] 37 c4 }

  condition:
    any of them
}