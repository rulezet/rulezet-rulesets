rule TTP_XOR_QUAD_CurrentVersionRun_a86e {
  strings:
    $key_a86e = { fb 01 [2] df 0f [2] f4 23 [2] da 01 [2] ce 1a [2] c1 00 [2] df 1d [2] dd 1c [2] c6 1a [2] da 1d [2] c6 32 }

  condition:
    any of them
}