rule TTP_XOR_QUAD_CurrentVersionRun_a0a6 {
  strings:
    $key_a0a6 = { f3 c9 [2] d7 c7 [2] fc eb [2] d2 c9 [2] c6 d2 [2] c9 c8 [2] d7 d5 [2] d5 d4 [2] ce d2 [2] d2 d5 [2] ce fa }

  condition:
    any of them
}