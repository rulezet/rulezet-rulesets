rule TTP_XOR_QUAD_CurrentVersionRun_a0e0 {
  strings:
    $key_a0e0 = { f3 8f [2] d7 81 [2] fc ad [2] d2 8f [2] c6 94 [2] c9 8e [2] d7 93 [2] d5 92 [2] ce 94 [2] d2 93 [2] ce bc }

  condition:
    any of them
}