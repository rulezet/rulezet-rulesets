rule TTP_XOR_QUAD_CurrentVersionRun_aa3f {
  strings:
    $key_aa3f = { f9 50 [2] dd 5e [2] f6 72 [2] d8 50 [2] cc 4b [2] c3 51 [2] dd 4c [2] df 4d [2] c4 4b [2] d8 4c [2] c4 63 }

  condition:
    any of them
}