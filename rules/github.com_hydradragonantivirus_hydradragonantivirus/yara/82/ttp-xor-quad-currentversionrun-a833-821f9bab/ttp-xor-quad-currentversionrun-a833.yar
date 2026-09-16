rule TTP_XOR_QUAD_CurrentVersionRun_a833 {
  strings:
    $key_a833 = { fb 5c [2] df 52 [2] f4 7e [2] da 5c [2] ce 47 [2] c1 5d [2] df 40 [2] dd 41 [2] c6 47 [2] da 40 [2] c6 6f }

  condition:
    any of them
}