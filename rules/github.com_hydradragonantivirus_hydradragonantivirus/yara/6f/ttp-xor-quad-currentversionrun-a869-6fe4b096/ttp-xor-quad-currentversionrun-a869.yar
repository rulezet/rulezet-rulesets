rule TTP_XOR_QUAD_CurrentVersionRun_a869 {
  strings:
    $key_a869 = { fb 06 [2] df 08 [2] f4 24 [2] da 06 [2] ce 1d [2] c1 07 [2] df 1a [2] dd 1b [2] c6 1d [2] da 1a [2] c6 35 }

  condition:
    any of them
}