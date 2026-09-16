rule TTP_XOR_QUAD_CurrentVersionRun_a825 {
  strings:
    $key_a825 = { fb 4a [2] df 44 [2] f4 68 [2] da 4a [2] ce 51 [2] c1 4b [2] df 56 [2] dd 57 [2] c6 51 [2] da 56 [2] c6 79 }

  condition:
    any of them
}