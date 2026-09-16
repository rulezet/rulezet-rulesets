rule TTP_XOR_QUAD_CurrentVersionRun_aafa {
  strings:
    $key_aafa = { f9 95 [2] dd 9b [2] f6 b7 [2] d8 95 [2] cc 8e [2] c3 94 [2] dd 89 [2] df 88 [2] c4 8e [2] d8 89 [2] c4 a6 }

  condition:
    any of them
}