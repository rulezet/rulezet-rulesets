rule TTP_XOR_QUAD_CurrentVersionRun_a5ea {
  strings:
    $key_a5ea = { f6 85 [2] d2 8b [2] f9 a7 [2] d7 85 [2] c3 9e [2] cc 84 [2] d2 99 [2] d0 98 [2] cb 9e [2] d7 99 [2] cb b6 }

  condition:
    any of them
}