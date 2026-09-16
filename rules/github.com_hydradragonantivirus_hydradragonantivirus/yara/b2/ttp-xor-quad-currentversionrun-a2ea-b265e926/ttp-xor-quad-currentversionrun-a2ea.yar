rule TTP_XOR_QUAD_CurrentVersionRun_a2ea {
  strings:
    $key_a2ea = { f1 85 [2] d5 8b [2] fe a7 [2] d0 85 [2] c4 9e [2] cb 84 [2] d5 99 [2] d7 98 [2] cc 9e [2] d0 99 [2] cc b6 }

  condition:
    any of them
}