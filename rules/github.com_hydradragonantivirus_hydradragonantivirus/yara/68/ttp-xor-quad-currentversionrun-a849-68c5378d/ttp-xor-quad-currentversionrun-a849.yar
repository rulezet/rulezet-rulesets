rule TTP_XOR_QUAD_CurrentVersionRun_a849 {
  strings:
    $key_a849 = { fb 26 [2] df 28 [2] f4 04 [2] da 26 [2] ce 3d [2] c1 27 [2] df 3a [2] dd 3b [2] c6 3d [2] da 3a [2] c6 15 }

  condition:
    any of them
}