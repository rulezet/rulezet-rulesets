rule TTP_XOR_QUAD_CurrentVersionRun_aaea {
  strings:
    $key_aaea = { f9 85 [2] dd 8b [2] f6 a7 [2] d8 85 [2] cc 9e [2] c3 84 [2] dd 99 [2] df 98 [2] c4 9e [2] d8 99 [2] c4 b6 }

  condition:
    any of them
}