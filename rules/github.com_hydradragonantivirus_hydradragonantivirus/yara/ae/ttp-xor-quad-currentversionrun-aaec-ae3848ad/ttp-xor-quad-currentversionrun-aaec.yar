rule TTP_XOR_QUAD_CurrentVersionRun_aaec {
  strings:
    $key_aaec = { f9 83 [2] dd 8d [2] f6 a1 [2] d8 83 [2] cc 98 [2] c3 82 [2] dd 9f [2] df 9e [2] c4 98 [2] d8 9f [2] c4 b0 }

  condition:
    any of them
}