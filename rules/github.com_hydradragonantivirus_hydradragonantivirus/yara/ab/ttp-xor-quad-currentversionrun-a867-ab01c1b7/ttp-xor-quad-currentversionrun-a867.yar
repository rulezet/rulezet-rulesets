rule TTP_XOR_QUAD_CurrentVersionRun_a867 {
  strings:
    $key_a867 = { fb 08 [2] df 06 [2] f4 2a [2] da 08 [2] ce 13 [2] c1 09 [2] df 14 [2] dd 15 [2] c6 13 [2] da 14 [2] c6 3b }

  condition:
    any of them
}