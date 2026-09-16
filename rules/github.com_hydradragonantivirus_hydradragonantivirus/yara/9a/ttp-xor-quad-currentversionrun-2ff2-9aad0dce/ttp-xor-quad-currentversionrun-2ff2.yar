rule TTP_XOR_QUAD_CurrentVersionRun_2ff2 {
  strings:
    $key_2ff2 = { 7c 9d [2] 58 93 [2] 73 bf [2] 5d 9d [2] 49 86 [2] 46 9c [2] 58 81 [2] 5a 80 [2] 41 86 [2] 5d 81 [2] 41 ae }

  condition:
    any of them
}