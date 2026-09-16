rule TTP_XOR_QUAD_CurrentVersionRun_a8ee {
  strings:
    $key_a8ee = { fb 81 [2] df 8f [2] f4 a3 [2] da 81 [2] ce 9a [2] c1 80 [2] df 9d [2] dd 9c [2] c6 9a [2] da 9d [2] c6 b2 }

  condition:
    any of them
}