rule TTP_XOR_QUAD_CurrentVersionRun_a811 {
  strings:
    $key_a811 = { fb 7e [2] df 70 [2] f4 5c [2] da 7e [2] ce 65 [2] c1 7f [2] df 62 [2] dd 63 [2] c6 65 [2] da 62 [2] c6 4d }

  condition:
    any of them
}