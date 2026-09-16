rule TTP_XOR_QUAD_CurrentVersionRun_6798 {
  strings:
    $key_6798 = { 34 f7 [2] 10 f9 [2] 3b d5 [2] 15 f7 [2] 01 ec [2] 0e f6 [2] 10 eb [2] 12 ea [2] 09 ec [2] 15 eb [2] 09 c4 }

  condition:
    any of them
}