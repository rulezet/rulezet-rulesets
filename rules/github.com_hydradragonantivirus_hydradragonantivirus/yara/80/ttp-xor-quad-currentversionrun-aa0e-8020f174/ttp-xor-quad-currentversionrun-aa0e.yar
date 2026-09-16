rule TTP_XOR_QUAD_CurrentVersionRun_aa0e {
  strings:
    $key_aa0e = { f9 61 [2] dd 6f [2] f6 43 [2] d8 61 [2] cc 7a [2] c3 60 [2] dd 7d [2] df 7c [2] c4 7a [2] d8 7d [2] c4 52 }

  condition:
    any of them
}