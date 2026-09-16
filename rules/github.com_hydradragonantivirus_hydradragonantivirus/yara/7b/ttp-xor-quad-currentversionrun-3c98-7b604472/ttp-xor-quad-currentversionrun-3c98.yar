rule TTP_XOR_QUAD_CurrentVersionRun_3c98 {
  strings:
    $key_3c98 = { 6f f7 [2] 4b f9 [2] 60 d5 [2] 4e f7 [2] 5a ec [2] 55 f6 [2] 4b eb [2] 49 ea [2] 52 ec [2] 4e eb [2] 52 c4 }

  condition:
    any of them
}