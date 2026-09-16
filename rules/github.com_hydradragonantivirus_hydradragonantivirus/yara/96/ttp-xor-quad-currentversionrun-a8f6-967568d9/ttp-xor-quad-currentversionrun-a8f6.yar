rule TTP_XOR_QUAD_CurrentVersionRun_a8f6 {
  strings:
    $key_a8f6 = { fb 99 [2] df 97 [2] f4 bb [2] da 99 [2] ce 82 [2] c1 98 [2] df 85 [2] dd 84 [2] c6 82 [2] da 85 [2] c6 aa }

  condition:
    any of them
}