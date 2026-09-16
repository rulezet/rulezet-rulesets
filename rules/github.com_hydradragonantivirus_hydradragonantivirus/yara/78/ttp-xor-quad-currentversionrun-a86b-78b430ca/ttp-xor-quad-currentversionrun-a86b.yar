rule TTP_XOR_QUAD_CurrentVersionRun_a86b {
  strings:
    $key_a86b = { fb 04 [2] df 0a [2] f4 26 [2] da 04 [2] ce 1f [2] c1 05 [2] df 18 [2] dd 19 [2] c6 1f [2] da 18 [2] c6 37 }

  condition:
    any of them
}