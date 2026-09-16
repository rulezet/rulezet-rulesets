rule TTP_XOR_QUAD_CurrentVersionRun_a8fc {
  strings:
    $key_a8fc = { fb 93 [2] df 9d [2] f4 b1 [2] da 93 [2] ce 88 [2] c1 92 [2] df 8f [2] dd 8e [2] c6 88 [2] da 8f [2] c6 a0 }

  condition:
    any of them
}