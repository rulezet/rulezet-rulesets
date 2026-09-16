rule TTP_XOR_QUAD_CurrentVersionRun_a832 {
  strings:
    $key_a832 = { fb 5d [2] df 53 [2] f4 7f [2] da 5d [2] ce 46 [2] c1 5c [2] df 41 [2] dd 40 [2] c6 46 [2] da 41 [2] c6 6e }

  condition:
    any of them
}