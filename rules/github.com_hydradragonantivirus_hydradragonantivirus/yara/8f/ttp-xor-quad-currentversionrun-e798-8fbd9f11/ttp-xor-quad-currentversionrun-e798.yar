rule TTP_XOR_QUAD_CurrentVersionRun_e798 {
  strings:
    $key_e798 = { b4 f7 [2] 90 f9 [2] bb d5 [2] 95 f7 [2] 81 ec [2] 8e f6 [2] 90 eb [2] 92 ea [2] 89 ec [2] 95 eb [2] 89 c4 }

  condition:
    any of them
}