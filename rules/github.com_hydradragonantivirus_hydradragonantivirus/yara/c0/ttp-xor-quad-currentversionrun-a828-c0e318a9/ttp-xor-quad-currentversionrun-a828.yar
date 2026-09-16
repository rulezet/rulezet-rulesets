rule TTP_XOR_QUAD_CurrentVersionRun_a828 {
  strings:
    $key_a828 = { fb 47 [2] df 49 [2] f4 65 [2] da 47 [2] ce 5c [2] c1 46 [2] df 5b [2] dd 5a [2] c6 5c [2] da 5b [2] c6 74 }

  condition:
    any of them
}