rule TTP_XOR_QUAD_CurrentVersionRun_a876 {
  strings:
    $key_a876 = { fb 19 [2] df 17 [2] f4 3b [2] da 19 [2] ce 02 [2] c1 18 [2] df 05 [2] dd 04 [2] c6 02 [2] da 05 [2] c6 2a }

  condition:
    any of them
}