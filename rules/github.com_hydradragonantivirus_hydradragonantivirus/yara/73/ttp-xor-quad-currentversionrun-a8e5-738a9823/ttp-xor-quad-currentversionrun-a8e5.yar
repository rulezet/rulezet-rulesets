rule TTP_XOR_QUAD_CurrentVersionRun_a8e5 {
  strings:
    $key_a8e5 = { fb 8a [2] df 84 [2] f4 a8 [2] da 8a [2] ce 91 [2] c1 8b [2] df 96 [2] dd 97 [2] c6 91 [2] da 96 [2] c6 b9 }

  condition:
    any of them
}