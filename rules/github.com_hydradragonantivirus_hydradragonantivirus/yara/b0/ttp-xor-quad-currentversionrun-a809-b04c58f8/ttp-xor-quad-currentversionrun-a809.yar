rule TTP_XOR_QUAD_CurrentVersionRun_a809 {
  strings:
    $key_a809 = { fb 66 [2] df 68 [2] f4 44 [2] da 66 [2] ce 7d [2] c1 67 [2] df 7a [2] dd 7b [2] c6 7d [2] da 7a [2] c6 55 }

  condition:
    any of them
}