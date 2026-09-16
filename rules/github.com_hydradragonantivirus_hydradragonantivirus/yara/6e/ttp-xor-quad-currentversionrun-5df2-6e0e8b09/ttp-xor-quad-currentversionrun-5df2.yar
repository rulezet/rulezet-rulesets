rule TTP_XOR_QUAD_CurrentVersionRun_5df2 {
  strings:
    $key_5df2 = { 0e 9d [2] 2a 93 [2] 01 bf [2] 2f 9d [2] 3b 86 [2] 34 9c [2] 2a 81 [2] 28 80 [2] 33 86 [2] 2f 81 [2] 33 ae }

  condition:
    any of them
}