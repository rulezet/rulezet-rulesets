rule TTP_XOR_QUAD_CurrentVersionRun_a818 {
  strings:
    $key_a818 = { fb 77 [2] df 79 [2] f4 55 [2] da 77 [2] ce 6c [2] c1 76 [2] df 6b [2] dd 6a [2] c6 6c [2] da 6b [2] c6 44 }

  condition:
    any of them
}