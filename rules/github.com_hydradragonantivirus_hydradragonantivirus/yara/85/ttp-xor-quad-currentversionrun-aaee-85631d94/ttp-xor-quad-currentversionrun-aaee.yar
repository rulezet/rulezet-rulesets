rule TTP_XOR_QUAD_CurrentVersionRun_aaee {
  strings:
    $key_aaee = { f9 81 [2] dd 8f [2] f6 a3 [2] d8 81 [2] cc 9a [2] c3 80 [2] dd 9d [2] df 9c [2] c4 9a [2] d8 9d [2] c4 b2 }

  condition:
    any of them
}