rule TTP_XOR_QUAD_CurrentVersionRun_aafc {
  strings:
    $key_aafc = { f9 93 [2] dd 9d [2] f6 b1 [2] d8 93 [2] cc 88 [2] c3 92 [2] dd 8f [2] df 8e [2] c4 88 [2] d8 8f [2] c4 a0 }

  condition:
    any of them
}