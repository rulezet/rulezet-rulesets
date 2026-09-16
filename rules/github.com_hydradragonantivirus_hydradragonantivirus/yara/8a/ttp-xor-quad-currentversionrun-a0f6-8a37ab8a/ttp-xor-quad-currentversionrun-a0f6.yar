rule TTP_XOR_QUAD_CurrentVersionRun_a0f6 {
  strings:
    $key_a0f6 = { f3 99 [2] d7 97 [2] fc bb [2] d2 99 [2] c6 82 [2] c9 98 [2] d7 85 [2] d5 84 [2] ce 82 [2] d2 85 [2] ce aa }

  condition:
    any of them
}