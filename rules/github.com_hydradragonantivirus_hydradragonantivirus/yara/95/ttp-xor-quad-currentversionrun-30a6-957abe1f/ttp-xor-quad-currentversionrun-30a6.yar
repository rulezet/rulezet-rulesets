rule TTP_XOR_QUAD_CurrentVersionRun_30a6 {
  strings:
    $key_30a6 = { 63 c9 [2] 47 c7 [2] 6c eb [2] 42 c9 [2] 56 d2 [2] 59 c8 [2] 47 d5 [2] 45 d4 [2] 5e d2 [2] 42 d5 [2] 5e fa }

  condition:
    any of them
}