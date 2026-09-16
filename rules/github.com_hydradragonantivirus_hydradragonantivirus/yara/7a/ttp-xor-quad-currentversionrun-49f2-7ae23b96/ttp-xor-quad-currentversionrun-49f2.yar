rule TTP_XOR_QUAD_CurrentVersionRun_49f2 {
  strings:
    $key_49f2 = { 1a 9d [2] 3e 93 [2] 15 bf [2] 3b 9d [2] 2f 86 [2] 20 9c [2] 3e 81 [2] 3c 80 [2] 27 86 [2] 3b 81 [2] 27 ae }

  condition:
    any of them
}