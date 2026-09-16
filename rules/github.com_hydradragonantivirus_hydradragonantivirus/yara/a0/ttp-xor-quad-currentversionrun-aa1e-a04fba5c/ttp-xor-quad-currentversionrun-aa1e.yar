rule TTP_XOR_QUAD_CurrentVersionRun_aa1e {
  strings:
    $key_aa1e = { f9 71 [2] dd 7f [2] f6 53 [2] d8 71 [2] cc 6a [2] c3 70 [2] dd 6d [2] df 6c [2] c4 6a [2] d8 6d [2] c4 42 }

  condition:
    any of them
}