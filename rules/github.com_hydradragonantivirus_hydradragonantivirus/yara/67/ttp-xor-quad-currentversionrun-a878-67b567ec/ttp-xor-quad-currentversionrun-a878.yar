rule TTP_XOR_QUAD_CurrentVersionRun_a878 {
  strings:
    $key_a878 = { fb 17 [2] df 19 [2] f4 35 [2] da 17 [2] ce 0c [2] c1 16 [2] df 0b [2] dd 0a [2] c6 0c [2] da 0b [2] c6 24 }

  condition:
    any of them
}