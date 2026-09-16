rule TTP_XOR_QUAD_CurrentVersionRun_74f2 {
  strings:
    $key_74f2 = { 27 9d [2] 03 93 [2] 28 bf [2] 06 9d [2] 12 86 [2] 1d 9c [2] 03 81 [2] 01 80 [2] 1a 86 [2] 06 81 [2] 1a ae }

  condition:
    any of them
}