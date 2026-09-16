rule TTP_XOR_QUAD_CurrentVersionRun_a824 {
  strings:
    $key_a824 = { fb 4b [2] df 45 [2] f4 69 [2] da 4b [2] ce 50 [2] c1 4a [2] df 57 [2] dd 56 [2] c6 50 [2] da 57 [2] c6 78 }

  condition:
    any of them
}