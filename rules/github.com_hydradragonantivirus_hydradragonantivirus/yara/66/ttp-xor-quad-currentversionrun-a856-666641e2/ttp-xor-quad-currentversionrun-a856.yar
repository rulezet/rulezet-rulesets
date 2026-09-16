rule TTP_XOR_QUAD_CurrentVersionRun_a856 {
  strings:
    $key_a856 = { fb 39 [2] df 37 [2] f4 1b [2] da 39 [2] ce 22 [2] c1 38 [2] df 25 [2] dd 24 [2] c6 22 [2] da 25 [2] c6 0a }

  condition:
    any of them
}