rule TTP_XOR_QUAD_CurrentVersionRun_2af2 {
  strings:
    $key_2af2 = { 79 9d [2] 5d 93 [2] 76 bf [2] 58 9d [2] 4c 86 [2] 43 9c [2] 5d 81 [2] 5f 80 [2] 44 86 [2] 58 81 [2] 44 ae }

  condition:
    any of them
}