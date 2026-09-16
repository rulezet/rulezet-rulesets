rule TTP_XOR_QUAD_CurrentVersionRun_37a6 {
  strings:
    $key_37a6 = { 64 c9 [2] 40 c7 [2] 6b eb [2] 45 c9 [2] 51 d2 [2] 5e c8 [2] 40 d5 [2] 42 d4 [2] 59 d2 [2] 45 d5 [2] 59 fa }

  condition:
    any of them
}