rule TTP_XOR_QUAD_CurrentVersionRun_7c98 {
  strings:
    $key_7c98 = { 2f f7 [2] 0b f9 [2] 20 d5 [2] 0e f7 [2] 1a ec [2] 15 f6 [2] 0b eb [2] 09 ea [2] 12 ec [2] 0e eb [2] 12 c4 }

  condition:
    any of them
}