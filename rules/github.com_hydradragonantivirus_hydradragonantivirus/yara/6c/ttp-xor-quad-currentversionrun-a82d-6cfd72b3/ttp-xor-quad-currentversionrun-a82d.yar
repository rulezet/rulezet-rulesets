rule TTP_XOR_QUAD_CurrentVersionRun_a82d {
  strings:
    $key_a82d = { fb 42 [2] df 4c [2] f4 60 [2] da 42 [2] ce 59 [2] c1 43 [2] df 5e [2] dd 5f [2] c6 59 [2] da 5e [2] c6 71 }

  condition:
    any of them
}