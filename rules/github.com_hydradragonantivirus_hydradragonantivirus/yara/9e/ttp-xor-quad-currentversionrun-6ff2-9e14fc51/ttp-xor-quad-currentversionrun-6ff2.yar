rule TTP_XOR_QUAD_CurrentVersionRun_6ff2 {
  strings:
    $key_6ff2 = { 3c 9d [2] 18 93 [2] 33 bf [2] 1d 9d [2] 09 86 [2] 06 9c [2] 18 81 [2] 1a 80 [2] 01 86 [2] 1d 81 [2] 01 ae }

  condition:
    any of them
}