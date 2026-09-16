rule TTP_XOR_QUAD_CurrentVersionRun_4998 {
  strings:
    $key_4998 = { 1a f7 [2] 3e f9 [2] 15 d5 [2] 3b f7 [2] 2f ec [2] 20 f6 [2] 3e eb [2] 3c ea [2] 27 ec [2] 3b eb [2] 27 c4 }

  condition:
    any of them
}