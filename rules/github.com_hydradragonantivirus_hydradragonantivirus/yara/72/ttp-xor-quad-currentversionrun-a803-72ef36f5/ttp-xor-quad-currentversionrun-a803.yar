rule TTP_XOR_QUAD_CurrentVersionRun_a803 {
  strings:
    $key_a803 = { fb 6c [2] df 62 [2] f4 4e [2] da 6c [2] ce 77 [2] c1 6d [2] df 70 [2] dd 71 [2] c6 77 [2] da 70 [2] c6 5f }

  condition:
    any of them
}