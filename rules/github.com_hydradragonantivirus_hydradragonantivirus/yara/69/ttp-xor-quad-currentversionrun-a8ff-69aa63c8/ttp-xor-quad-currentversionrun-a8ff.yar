rule TTP_XOR_QUAD_CurrentVersionRun_a8ff {
  strings:
    $key_a8ff = { fb 90 [2] df 9e [2] f4 b2 [2] da 90 [2] ce 8b [2] c1 91 [2] df 8c [2] dd 8d [2] c6 8b [2] da 8c [2] c6 a3 }

  condition:
    any of them
}