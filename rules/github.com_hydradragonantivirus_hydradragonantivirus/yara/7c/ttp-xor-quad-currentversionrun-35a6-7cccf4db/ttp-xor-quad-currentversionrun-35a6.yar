rule TTP_XOR_QUAD_CurrentVersionRun_35a6 {
  strings:
    $key_35a6 = { 66 c9 [2] 42 c7 [2] 69 eb [2] 47 c9 [2] 53 d2 [2] 5c c8 [2] 42 d5 [2] 40 d4 [2] 5b d2 [2] 47 d5 [2] 5b fa }

  condition:
    any of them
}