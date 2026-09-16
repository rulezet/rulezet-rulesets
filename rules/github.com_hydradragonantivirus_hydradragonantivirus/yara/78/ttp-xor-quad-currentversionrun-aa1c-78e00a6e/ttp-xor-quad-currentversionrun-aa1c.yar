rule TTP_XOR_QUAD_CurrentVersionRun_aa1c {
  strings:
    $key_aa1c = { f9 73 [2] dd 7d [2] f6 51 [2] d8 73 [2] cc 68 [2] c3 72 [2] dd 6f [2] df 6e [2] c4 68 [2] d8 6f [2] c4 40 }

  condition:
    any of them
}