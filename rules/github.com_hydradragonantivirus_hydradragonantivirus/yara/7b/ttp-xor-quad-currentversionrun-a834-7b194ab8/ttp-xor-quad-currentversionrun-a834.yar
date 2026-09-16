rule TTP_XOR_QUAD_CurrentVersionRun_a834 {
  strings:
    $key_a834 = { fb 5b [2] df 55 [2] f4 79 [2] da 5b [2] ce 40 [2] c1 5a [2] df 47 [2] dd 46 [2] c6 40 [2] da 47 [2] c6 68 }

  condition:
    any of them
}