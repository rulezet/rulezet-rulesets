rule TTP_XOR_QUAD_CurrentVersionRun_a83f {
  strings:
    $key_a83f = { fb 50 [2] df 5e [2] f4 72 [2] da 50 [2] ce 4b [2] c1 51 [2] df 4c [2] dd 4d [2] c6 4b [2] da 4c [2] c6 63 }

  condition:
    any of them
}