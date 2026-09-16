rule TTP_XOR_QUAD_CurrentVersionRun_a86f {
  strings:
    $key_a86f = { fb 00 [2] df 0e [2] f4 22 [2] da 00 [2] ce 1b [2] c1 01 [2] df 1c [2] dd 1d [2] c6 1b [2] da 1c [2] c6 33 }

  condition:
    any of them
}