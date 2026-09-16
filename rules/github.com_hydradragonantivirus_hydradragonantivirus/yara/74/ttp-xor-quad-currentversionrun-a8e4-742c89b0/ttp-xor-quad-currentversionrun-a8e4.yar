rule TTP_XOR_QUAD_CurrentVersionRun_a8e4 {
  strings:
    $key_a8e4 = { fb 8b [2] df 85 [2] f4 a9 [2] da 8b [2] ce 90 [2] c1 8a [2] df 97 [2] dd 96 [2] c6 90 [2] da 97 [2] c6 b8 }

  condition:
    any of them
}