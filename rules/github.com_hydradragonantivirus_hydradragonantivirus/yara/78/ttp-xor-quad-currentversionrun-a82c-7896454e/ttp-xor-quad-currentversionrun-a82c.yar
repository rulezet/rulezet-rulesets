rule TTP_XOR_QUAD_CurrentVersionRun_a82c {
  strings:
    $key_a82c = { fb 43 [2] df 4d [2] f4 61 [2] da 43 [2] ce 58 [2] c1 42 [2] df 5f [2] dd 5e [2] c6 58 [2] da 5f [2] c6 70 }

  condition:
    any of them
}