rule TTP_XOR_QUAD_CurrentVersionRun_a8f8 {
  strings:
    $key_a8f8 = { fb 97 [2] df 99 [2] f4 b5 [2] da 97 [2] ce 8c [2] c1 96 [2] df 8b [2] dd 8a [2] c6 8c [2] da 8b [2] c6 a4 }

  condition:
    any of them
}