rule TTP_XOR_QUAD_CurrentVersionRun_a879 {
  strings:
    $key_a879 = { fb 16 [2] df 18 [2] f4 34 [2] da 16 [2] ce 0d [2] c1 17 [2] df 0a [2] dd 0b [2] c6 0d [2] da 0a [2] c6 25 }

  condition:
    any of them
}