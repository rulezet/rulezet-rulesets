rule TTP_XOR_QUAD_CurrentVersionRun_2299 {
  strings:
    $key_2299 = { 71 f6 [2] 55 f8 [2] 7e d4 [2] 50 f6 [2] 44 ed [2] 4b f7 [2] 55 ea [2] 57 eb [2] 4c ed [2] 50 ea [2] 4c c5 }

  condition:
    any of them
}