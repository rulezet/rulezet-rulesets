rule TTP_XOR_QUAD_CurrentVersionRun_cff2 {
  strings:
    $key_cff2 = { 9c 9d [2] b8 93 [2] 93 bf [2] bd 9d [2] a9 86 [2] a6 9c [2] b8 81 [2] ba 80 [2] a1 86 [2] bd 81 [2] a1 ae }

  condition:
    any of them
}