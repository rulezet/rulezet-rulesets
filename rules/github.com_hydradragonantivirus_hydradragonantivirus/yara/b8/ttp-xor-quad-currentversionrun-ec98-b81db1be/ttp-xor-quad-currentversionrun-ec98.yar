rule TTP_XOR_QUAD_CurrentVersionRun_ec98 {
  strings:
    $key_ec98 = { bf f7 [2] 9b f9 [2] b0 d5 [2] 9e f7 [2] 8a ec [2] 85 f6 [2] 9b eb [2] 99 ea [2] 82 ec [2] 9e eb [2] 82 c4 }

  condition:
    any of them
}