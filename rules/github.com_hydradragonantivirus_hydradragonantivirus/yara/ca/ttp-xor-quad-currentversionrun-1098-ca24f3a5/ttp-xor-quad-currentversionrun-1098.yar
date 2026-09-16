rule TTP_XOR_QUAD_CurrentVersionRun_1098 {
  strings:
    $key_1098 = { 43 f7 [2] 67 f9 [2] 4c d5 [2] 62 f7 [2] 76 ec [2] 79 f6 [2] 67 eb [2] 65 ea [2] 7e ec [2] 62 eb [2] 7e c4 }

  condition:
    any of them
}