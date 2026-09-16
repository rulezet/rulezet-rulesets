rule TTP_XOR_QUAD_CurrentVersionRun_15f2 {
  strings:
    $key_15f2 = { 46 9d [2] 62 93 [2] 49 bf [2] 67 9d [2] 73 86 [2] 7c 9c [2] 62 81 [2] 60 80 [2] 7b 86 [2] 67 81 [2] 7b ae }

  condition:
    any of them
}