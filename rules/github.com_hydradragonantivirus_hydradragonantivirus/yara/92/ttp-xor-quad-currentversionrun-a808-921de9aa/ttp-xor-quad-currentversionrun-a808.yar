rule TTP_XOR_QUAD_CurrentVersionRun_a808 {
  strings:
    $key_a808 = { fb 67 [2] df 69 [2] f4 45 [2] da 67 [2] ce 7c [2] c1 66 [2] df 7b [2] dd 7a [2] c6 7c [2] da 7b [2] c6 54 }

  condition:
    any of them
}