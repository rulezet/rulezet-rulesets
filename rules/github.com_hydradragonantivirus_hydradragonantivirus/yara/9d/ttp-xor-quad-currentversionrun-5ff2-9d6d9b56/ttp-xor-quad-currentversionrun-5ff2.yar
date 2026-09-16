rule TTP_XOR_QUAD_CurrentVersionRun_5ff2 {
  strings:
    $key_5ff2 = { 0c 9d [2] 28 93 [2] 03 bf [2] 2d 9d [2] 39 86 [2] 36 9c [2] 28 81 [2] 2a 80 [2] 31 86 [2] 2d 81 [2] 31 ae }

  condition:
    any of them
}