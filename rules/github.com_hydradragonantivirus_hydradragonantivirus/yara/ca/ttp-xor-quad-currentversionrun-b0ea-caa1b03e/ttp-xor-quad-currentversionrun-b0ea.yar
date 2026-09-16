rule TTP_XOR_QUAD_CurrentVersionRun_b0ea {
  strings:
    $key_b0ea = { e3 85 [2] c7 8b [2] ec a7 [2] c2 85 [2] d6 9e [2] d9 84 [2] c7 99 [2] c5 98 [2] de 9e [2] c2 99 [2] de b6 }

  condition:
    any of them
}