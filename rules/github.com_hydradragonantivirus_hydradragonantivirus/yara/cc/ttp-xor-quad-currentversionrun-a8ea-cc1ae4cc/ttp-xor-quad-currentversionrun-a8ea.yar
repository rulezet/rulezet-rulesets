rule TTP_XOR_QUAD_CurrentVersionRun_a8ea {
  strings:
    $key_a8ea = { fb 85 [2] df 8b [2] f4 a7 [2] da 85 [2] ce 9e [2] c1 84 [2] df 99 [2] dd 98 [2] c6 9e [2] da 99 [2] c6 b6 }

  condition:
    any of them
}