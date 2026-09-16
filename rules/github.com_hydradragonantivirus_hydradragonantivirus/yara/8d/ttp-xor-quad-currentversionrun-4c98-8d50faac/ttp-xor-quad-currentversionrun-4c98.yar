rule TTP_XOR_QUAD_CurrentVersionRun_4c98 {
  strings:
    $key_4c98 = { 1f f7 [2] 3b f9 [2] 10 d5 [2] 3e f7 [2] 2a ec [2] 25 f6 [2] 3b eb [2] 39 ea [2] 22 ec [2] 3e eb [2] 22 c4 }

  condition:
    any of them
}