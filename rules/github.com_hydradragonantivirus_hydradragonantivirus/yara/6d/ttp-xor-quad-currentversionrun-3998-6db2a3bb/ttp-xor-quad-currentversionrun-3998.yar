rule TTP_XOR_QUAD_CurrentVersionRun_3998 {
  strings:
    $key_3998 = { 6a f7 [2] 4e f9 [2] 65 d5 [2] 4b f7 [2] 5f ec [2] 50 f6 [2] 4e eb [2] 4c ea [2] 57 ec [2] 4b eb [2] 57 c4 }

  condition:
    any of them
}