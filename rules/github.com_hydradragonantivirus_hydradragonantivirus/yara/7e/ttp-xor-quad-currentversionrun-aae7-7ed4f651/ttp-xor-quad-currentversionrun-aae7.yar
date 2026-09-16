rule TTP_XOR_QUAD_CurrentVersionRun_aae7 {
  strings:
    $key_aae7 = { f9 88 [2] dd 86 [2] f6 aa [2] d8 88 [2] cc 93 [2] c3 89 [2] dd 94 [2] df 95 [2] c4 93 [2] d8 94 [2] c4 bb }

  condition:
    any of them
}