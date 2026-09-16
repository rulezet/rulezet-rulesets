rule TTP_XOR_QUAD_CurrentVersionRun_a820 {
  strings:
    $key_a820 = { fb 4f [2] df 41 [2] f4 6d [2] da 4f [2] ce 54 [2] c1 4e [2] df 53 [2] dd 52 [2] c6 54 [2] da 53 [2] c6 7c }

  condition:
    any of them
}