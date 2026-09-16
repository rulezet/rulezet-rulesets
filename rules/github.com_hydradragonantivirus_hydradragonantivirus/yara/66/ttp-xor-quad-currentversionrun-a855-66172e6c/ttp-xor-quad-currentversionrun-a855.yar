rule TTP_XOR_QUAD_CurrentVersionRun_a855 {
  strings:
    $key_a855 = { fb 3a [2] df 34 [2] f4 18 [2] da 3a [2] ce 21 [2] c1 3b [2] df 26 [2] dd 27 [2] c6 21 [2] da 26 [2] c6 09 }

  condition:
    any of them
}