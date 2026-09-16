rule TTP_XOR_QUAD_CurrentVersionRun_a839 {
  strings:
    $key_a839 = { fb 56 [2] df 58 [2] f4 74 [2] da 56 [2] ce 4d [2] c1 57 [2] df 4a [2] dd 4b [2] c6 4d [2] da 4a [2] c6 65 }

  condition:
    any of them
}