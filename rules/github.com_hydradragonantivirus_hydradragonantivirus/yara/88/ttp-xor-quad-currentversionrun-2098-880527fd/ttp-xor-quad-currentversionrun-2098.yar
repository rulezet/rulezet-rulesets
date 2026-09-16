rule TTP_XOR_QUAD_CurrentVersionRun_2098 {
  strings:
    $key_2098 = { 73 f7 [2] 57 f9 [2] 7c d5 [2] 52 f7 [2] 46 ec [2] 49 f6 [2] 57 eb [2] 55 ea [2] 4e ec [2] 52 eb [2] 4e c4 }

  condition:
    any of them
}