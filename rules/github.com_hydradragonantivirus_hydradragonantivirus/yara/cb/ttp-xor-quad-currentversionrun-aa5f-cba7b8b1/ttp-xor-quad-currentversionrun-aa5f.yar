rule TTP_XOR_QUAD_CurrentVersionRun_aa5f {
  strings:
    $key_aa5f = { f9 30 [2] dd 3e [2] f6 12 [2] d8 30 [2] cc 2b [2] c3 31 [2] dd 2c [2] df 2d [2] c4 2b [2] d8 2c [2] c4 03 }

  condition:
    any of them
}