rule TTP_XOR_QUAD_CurrentVersionRun_aa0a {
  strings:
    $key_aa0a = { f9 65 [2] dd 6b [2] f6 47 [2] d8 65 [2] cc 7e [2] c3 64 [2] dd 79 [2] df 78 [2] c4 7e [2] d8 79 [2] c4 56 }

  condition:
    any of them
}