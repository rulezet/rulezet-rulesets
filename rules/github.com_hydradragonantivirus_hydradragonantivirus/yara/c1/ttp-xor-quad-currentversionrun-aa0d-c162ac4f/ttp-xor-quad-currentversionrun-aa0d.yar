rule TTP_XOR_QUAD_CurrentVersionRun_aa0d {
  strings:
    $key_aa0d = { f9 62 [2] dd 6c [2] f6 40 [2] d8 62 [2] cc 79 [2] c3 63 [2] dd 7e [2] df 7f [2] c4 79 [2] d8 7e [2] c4 51 }

  condition:
    any of them
}