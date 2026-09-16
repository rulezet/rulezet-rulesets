rule TTP_XOR_QUAD_CurrentVersionRun_a857 {
  strings:
    $key_a857 = { fb 38 [2] df 36 [2] f4 1a [2] da 38 [2] ce 23 [2] c1 39 [2] df 24 [2] dd 25 [2] c6 23 [2] da 24 [2] c6 0b }

  condition:
    any of them
}