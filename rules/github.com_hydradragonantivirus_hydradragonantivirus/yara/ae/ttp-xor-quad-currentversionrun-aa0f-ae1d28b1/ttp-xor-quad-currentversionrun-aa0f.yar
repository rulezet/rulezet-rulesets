rule TTP_XOR_QUAD_CurrentVersionRun_aa0f {
  strings:
    $key_aa0f = { f9 60 [2] dd 6e [2] f6 42 [2] d8 60 [2] cc 7b [2] c3 61 [2] dd 7c [2] df 7d [2] c4 7b [2] d8 7c [2] c4 53 }

  condition:
    any of them
}