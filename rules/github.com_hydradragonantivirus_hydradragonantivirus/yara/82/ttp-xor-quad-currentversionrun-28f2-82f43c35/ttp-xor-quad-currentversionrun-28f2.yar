rule TTP_XOR_QUAD_CurrentVersionRun_28f2 {
  strings:
    $key_28f2 = { 7b 9d [2] 5f 93 [2] 74 bf [2] 5a 9d [2] 4e 86 [2] 41 9c [2] 5f 81 [2] 5d 80 [2] 46 86 [2] 5a 81 [2] 46 ae }

  condition:
    any of them
}