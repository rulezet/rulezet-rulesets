rule TTP_XOR_QUAD_CurrentVersionRun_a872 {
  strings:
    $key_a872 = { fb 1d [2] df 13 [2] f4 3f [2] da 1d [2] ce 06 [2] c1 1c [2] df 01 [2] dd 00 [2] c6 06 [2] da 01 [2] c6 2e }

  condition:
    any of them
}