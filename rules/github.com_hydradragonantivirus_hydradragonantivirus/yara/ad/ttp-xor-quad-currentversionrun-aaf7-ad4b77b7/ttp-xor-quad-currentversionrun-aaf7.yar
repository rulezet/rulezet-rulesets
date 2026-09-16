rule TTP_XOR_QUAD_CurrentVersionRun_aaf7 {
  strings:
    $key_aaf7 = { f9 98 [2] dd 96 [2] f6 ba [2] d8 98 [2] cc 83 [2] c3 99 [2] dd 84 [2] df 85 [2] c4 83 [2] d8 84 [2] c4 ab }

  condition:
    any of them
}