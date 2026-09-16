rule TTP_XOR_QUAD_CurrentVersionRun_aae2 {
  strings:
    $key_aae2 = { f9 8d [2] dd 83 [2] f6 af [2] d8 8d [2] cc 96 [2] c3 8c [2] dd 91 [2] df 90 [2] c4 96 [2] d8 91 [2] c4 be }

  condition:
    any of them
}