rule TTP_XOR_QUAD_CurrentVersionRun_1af2 {
  strings:
    $key_1af2 = { 49 9d [2] 6d 93 [2] 46 bf [2] 68 9d [2] 7c 86 [2] 73 9c [2] 6d 81 [2] 6f 80 [2] 74 86 [2] 68 81 [2] 74 ae }

  condition:
    any of them
}