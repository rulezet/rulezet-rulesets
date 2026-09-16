rule TTP_XOR_QUAD_CurrentVersionRun_aa1f {
  strings:
    $key_aa1f = { f9 70 [2] dd 7e [2] f6 52 [2] d8 70 [2] cc 6b [2] c3 71 [2] dd 6c [2] df 6d [2] c4 6b [2] d8 6c [2] c4 43 }

  condition:
    any of them
}