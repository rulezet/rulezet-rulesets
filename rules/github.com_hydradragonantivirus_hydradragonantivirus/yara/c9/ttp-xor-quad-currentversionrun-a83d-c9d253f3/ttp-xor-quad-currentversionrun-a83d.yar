rule TTP_XOR_QUAD_CurrentVersionRun_a83d {
  strings:
    $key_a83d = { fb 52 [2] df 5c [2] f4 70 [2] da 52 [2] ce 49 [2] c1 53 [2] df 4e [2] dd 4f [2] c6 49 [2] da 4e [2] c6 61 }

  condition:
    any of them
}