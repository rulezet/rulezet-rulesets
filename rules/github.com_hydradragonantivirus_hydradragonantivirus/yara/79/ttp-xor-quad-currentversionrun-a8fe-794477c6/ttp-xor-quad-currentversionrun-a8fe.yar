rule TTP_XOR_QUAD_CurrentVersionRun_a8fe {
  strings:
    $key_a8fe = { fb 91 [2] df 9f [2] f4 b3 [2] da 91 [2] ce 8a [2] c1 90 [2] df 8d [2] dd 8c [2] c6 8a [2] da 8d [2] c6 a2 }

  condition:
    any of them
}