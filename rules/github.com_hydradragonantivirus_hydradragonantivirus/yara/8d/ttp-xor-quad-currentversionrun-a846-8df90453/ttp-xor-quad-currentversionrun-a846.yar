rule TTP_XOR_QUAD_CurrentVersionRun_a846 {
  strings:
    $key_a846 = { fb 29 [2] df 27 [2] f4 0b [2] da 29 [2] ce 32 [2] c1 28 [2] df 35 [2] dd 34 [2] c6 32 [2] da 35 [2] c6 1a }

  condition:
    any of them
}