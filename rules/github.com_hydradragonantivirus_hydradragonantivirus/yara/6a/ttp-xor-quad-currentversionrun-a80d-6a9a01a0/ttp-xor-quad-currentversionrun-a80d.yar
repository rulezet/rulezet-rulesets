rule TTP_XOR_QUAD_CurrentVersionRun_a80d {
  strings:
    $key_a80d = { fb 62 [2] df 6c [2] f4 40 [2] da 62 [2] ce 79 [2] c1 63 [2] df 7e [2] dd 7f [2] c6 79 [2] da 7e [2] c6 51 }

  condition:
    any of them
}