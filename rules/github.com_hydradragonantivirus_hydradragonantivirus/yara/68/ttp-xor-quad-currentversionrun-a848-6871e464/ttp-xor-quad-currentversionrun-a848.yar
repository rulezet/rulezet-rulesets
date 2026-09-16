rule TTP_XOR_QUAD_CurrentVersionRun_a848 {
  strings:
    $key_a848 = { fb 27 [2] df 29 [2] f4 05 [2] da 27 [2] ce 3c [2] c1 26 [2] df 3b [2] dd 3a [2] c6 3c [2] da 3b [2] c6 14 }

  condition:
    any of them
}