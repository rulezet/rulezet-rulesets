rule TTP_XOR_QUAD_CurrentVersionRun_a8e3 {
  strings:
    $key_a8e3 = { fb 8c [2] df 82 [2] f4 ae [2] da 8c [2] ce 97 [2] c1 8d [2] df 90 [2] dd 91 [2] c6 97 [2] da 90 [2] c6 bf }

  condition:
    any of them
}