rule TTP_XOR_QUAD_CurrentVersionRun_a84f {
  strings:
    $key_a84f = { fb 20 [2] df 2e [2] f4 02 [2] da 20 [2] ce 3b [2] c1 21 [2] df 3c [2] dd 3d [2] c6 3b [2] da 3c [2] c6 13 }

  condition:
    any of them
}