rule TTP_XOR_QUAD_CurrentVersionRun_65a6 {
  strings:
    $key_65a6 = { 36 c9 [2] 12 c7 [2] 39 eb [2] 17 c9 [2] 03 d2 [2] 0c c8 [2] 12 d5 [2] 10 d4 [2] 0b d2 [2] 17 d5 [2] 0b fa }

  condition:
    any of them
}