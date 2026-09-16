rule TTP_XOR_QUAD_CurrentVersionRun_a8e7 {
  strings:
    $key_a8e7 = { fb 88 [2] df 86 [2] f4 aa [2] da 88 [2] ce 93 [2] c1 89 [2] df 94 [2] dd 95 [2] c6 93 [2] da 94 [2] c6 bb }

  condition:
    any of them
}