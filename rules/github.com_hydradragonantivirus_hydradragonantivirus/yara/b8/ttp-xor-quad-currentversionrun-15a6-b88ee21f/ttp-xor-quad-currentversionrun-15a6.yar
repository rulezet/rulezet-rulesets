rule TTP_XOR_QUAD_CurrentVersionRun_15a6 {
  strings:
    $key_15a6 = { 46 c9 [2] 62 c7 [2] 49 eb [2] 67 c9 [2] 73 d2 [2] 7c c8 [2] 62 d5 [2] 60 d4 [2] 7b d2 [2] 67 d5 [2] 7b fa }

  condition:
    any of them
}