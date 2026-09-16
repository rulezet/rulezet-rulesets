rule TTP_XOR_QUAD_CurrentVersionRun_aaf2 {
  strings:
    $key_aaf2 = { f9 9d [2] dd 93 [2] f6 bf [2] d8 9d [2] cc 86 [2] c3 9c [2] dd 81 [2] df 80 [2] c4 86 [2] d8 81 [2] c4 ae }

  condition:
    any of them
}