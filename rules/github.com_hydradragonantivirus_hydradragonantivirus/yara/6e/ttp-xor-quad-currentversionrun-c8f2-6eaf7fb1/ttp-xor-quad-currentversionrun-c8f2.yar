rule TTP_XOR_QUAD_CurrentVersionRun_c8f2 {
  strings:
    $key_c8f2 = { 9b 9d [2] bf 93 [2] 94 bf [2] ba 9d [2] ae 86 [2] a1 9c [2] bf 81 [2] bd 80 [2] a6 86 [2] ba 81 [2] a6 ae }

  condition:
    any of them
}