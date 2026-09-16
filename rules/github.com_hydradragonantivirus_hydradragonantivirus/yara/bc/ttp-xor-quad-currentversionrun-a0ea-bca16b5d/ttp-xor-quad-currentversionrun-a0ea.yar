rule TTP_XOR_QUAD_CurrentVersionRun_a0ea {
  strings:
    $key_a0ea = { f3 85 [2] d7 8b [2] fc a7 [2] d2 85 [2] c6 9e [2] c9 84 [2] d7 99 [2] d5 98 [2] ce 9e [2] d2 99 [2] ce b6 }

  condition:
    any of them
}