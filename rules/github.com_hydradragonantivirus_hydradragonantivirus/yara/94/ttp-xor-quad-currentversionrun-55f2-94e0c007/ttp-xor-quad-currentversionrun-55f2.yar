rule TTP_XOR_QUAD_CurrentVersionRun_55f2 {
  strings:
    $key_55f2 = { 06 9d [2] 22 93 [2] 09 bf [2] 27 9d [2] 33 86 [2] 3c 9c [2] 22 81 [2] 20 80 [2] 3b 86 [2] 27 81 [2] 3b ae }

  condition:
    any of them
}