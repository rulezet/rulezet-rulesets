rule TTP_XOR_QUAD_CurrentVersionRun_a837 {
  strings:
    $key_a837 = { fb 58 [2] df 56 [2] f4 7a [2] da 58 [2] ce 43 [2] c1 59 [2] df 44 [2] dd 45 [2] c6 43 [2] da 44 [2] c6 6b }

  condition:
    any of them
}