rule TTP_XOR_QUAD_CurrentVersionRun_e8ea {
  strings:
    $key_e8ea = { bb 85 [2] 9f 8b [2] b4 a7 [2] 9a 85 [2] 8e 9e [2] 81 84 [2] 9f 99 [2] 9d 98 [2] 86 9e [2] 9a 99 [2] 86 b6 }

  condition:
    any of them
}