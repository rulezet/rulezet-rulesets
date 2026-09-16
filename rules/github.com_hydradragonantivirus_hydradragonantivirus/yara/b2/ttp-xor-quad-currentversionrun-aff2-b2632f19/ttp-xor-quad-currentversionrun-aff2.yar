rule TTP_XOR_QUAD_CurrentVersionRun_aff2 {
  strings:
    $key_aff2 = { fc 9d [2] d8 93 [2] f3 bf [2] dd 9d [2] c9 86 [2] c6 9c [2] d8 81 [2] da 80 [2] c1 86 [2] dd 81 [2] c1 ae }

  condition:
    any of them
}