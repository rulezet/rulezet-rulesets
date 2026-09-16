rule TTP_XOR_QUAD_CurrentVersionRun_a86c {
  strings:
    $key_a86c = { fb 03 [2] df 0d [2] f4 21 [2] da 03 [2] ce 18 [2] c1 02 [2] df 1f [2] dd 1e [2] c6 18 [2] da 1f [2] c6 30 }

  condition:
    any of them
}