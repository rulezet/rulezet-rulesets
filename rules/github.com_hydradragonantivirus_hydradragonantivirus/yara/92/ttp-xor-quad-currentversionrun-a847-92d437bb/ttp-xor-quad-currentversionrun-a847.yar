rule TTP_XOR_QUAD_CurrentVersionRun_a847 {
  strings:
    $key_a847 = { fb 28 [2] df 26 [2] f4 0a [2] da 28 [2] ce 33 [2] c1 29 [2] df 34 [2] dd 35 [2] c6 33 [2] da 34 [2] c6 1b }

  condition:
    any of them
}