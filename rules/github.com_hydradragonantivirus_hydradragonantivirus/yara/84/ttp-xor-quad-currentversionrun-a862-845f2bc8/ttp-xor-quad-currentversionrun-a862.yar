rule TTP_XOR_QUAD_CurrentVersionRun_a862 {
  strings:
    $key_a862 = { fb 0d [2] df 03 [2] f4 2f [2] da 0d [2] ce 16 [2] c1 0c [2] df 11 [2] dd 10 [2] c6 16 [2] da 11 [2] c6 3e }

  condition:
    any of them
}