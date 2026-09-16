rule TTP_XOR_QUAD_CurrentVersionRun_1ff2 {
  strings:
    $key_1ff2 = { 4c 9d [2] 68 93 [2] 43 bf [2] 6d 9d [2] 79 86 [2] 76 9c [2] 68 81 [2] 6a 80 [2] 71 86 [2] 6d 81 [2] 71 ae }

  condition:
    any of them
}