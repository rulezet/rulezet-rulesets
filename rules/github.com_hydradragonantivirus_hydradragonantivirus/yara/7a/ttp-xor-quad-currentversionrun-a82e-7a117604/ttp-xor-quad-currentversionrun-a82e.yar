rule TTP_XOR_QUAD_CurrentVersionRun_a82e {
  strings:
    $key_a82e = { fb 41 [2] df 4f [2] f4 63 [2] da 41 [2] ce 5a [2] c1 40 [2] df 5d [2] dd 5c [2] c6 5a [2] da 5d [2] c6 72 }

  condition:
    any of them
}