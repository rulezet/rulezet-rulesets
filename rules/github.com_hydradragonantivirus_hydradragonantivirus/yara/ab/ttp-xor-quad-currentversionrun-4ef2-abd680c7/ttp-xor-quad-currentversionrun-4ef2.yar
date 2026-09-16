rule TTP_XOR_QUAD_CurrentVersionRun_4ef2 {
  strings:
    $key_4ef2 = { 1d 9d [2] 39 93 [2] 12 bf [2] 3c 9d [2] 28 86 [2] 27 9c [2] 39 81 [2] 3b 80 [2] 20 86 [2] 3c 81 [2] 20 ae }

  condition:
    any of them
}