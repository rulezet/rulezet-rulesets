rule TTP_XOR_QUAD_CurrentVersionRun_a854 {
  strings:
    $key_a854 = { fb 3b [2] df 35 [2] f4 19 [2] da 3b [2] ce 20 [2] c1 3a [2] df 27 [2] dd 26 [2] c6 20 [2] da 27 [2] c6 08 }

  condition:
    any of them
}