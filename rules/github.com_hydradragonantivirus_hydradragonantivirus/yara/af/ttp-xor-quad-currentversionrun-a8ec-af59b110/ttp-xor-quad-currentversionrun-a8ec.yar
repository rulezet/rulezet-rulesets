rule TTP_XOR_QUAD_CurrentVersionRun_a8ec {
  strings:
    $key_a8ec = { fb 83 [2] df 8d [2] f4 a1 [2] da 83 [2] ce 98 [2] c1 82 [2] df 9f [2] dd 9e [2] c6 98 [2] da 9f [2] c6 b0 }

  condition:
    any of them
}