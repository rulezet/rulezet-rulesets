rule TTP_XOR_QUAD_CurrentVersionRun_a8ef {
  strings:
    $key_a8ef = { fb 80 [2] df 8e [2] f4 a2 [2] da 80 [2] ce 9b [2] c1 81 [2] df 9c [2] dd 9d [2] c6 9b [2] da 9c [2] c6 b3 }

  condition:
    any of them
}