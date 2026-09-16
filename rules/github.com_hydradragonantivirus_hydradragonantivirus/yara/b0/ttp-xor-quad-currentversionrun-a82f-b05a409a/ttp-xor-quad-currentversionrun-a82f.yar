rule TTP_XOR_QUAD_CurrentVersionRun_a82f {
  strings:
    $key_a82f = { fb 40 [2] df 4e [2] f4 62 [2] da 40 [2] ce 5b [2] c1 41 [2] df 5c [2] dd 5d [2] c6 5b [2] da 5c [2] c6 73 }

  condition:
    any of them
}