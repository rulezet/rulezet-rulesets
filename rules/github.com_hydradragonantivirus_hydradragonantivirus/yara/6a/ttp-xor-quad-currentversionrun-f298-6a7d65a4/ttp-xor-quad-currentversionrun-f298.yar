rule TTP_XOR_QUAD_CurrentVersionRun_f298 {
  strings:
    $key_f298 = { a1 f7 [2] 85 f9 [2] ae d5 [2] 80 f7 [2] 94 ec [2] 9b f6 [2] 85 eb [2] 87 ea [2] 9c ec [2] 80 eb [2] 9c c4 }

  condition:
    any of them
}