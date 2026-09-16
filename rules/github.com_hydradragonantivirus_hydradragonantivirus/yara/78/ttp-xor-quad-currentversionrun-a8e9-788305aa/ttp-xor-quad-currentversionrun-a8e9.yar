rule TTP_XOR_QUAD_CurrentVersionRun_a8e9 {
  strings:
    $key_a8e9 = { fb 86 [2] df 88 [2] f4 a4 [2] da 86 [2] ce 9d [2] c1 87 [2] df 9a [2] dd 9b [2] c6 9d [2] da 9a [2] c6 b5 }

  condition:
    any of them
}