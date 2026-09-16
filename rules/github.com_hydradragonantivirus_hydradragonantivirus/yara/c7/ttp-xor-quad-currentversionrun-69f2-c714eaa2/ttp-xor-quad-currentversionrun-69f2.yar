rule TTP_XOR_QUAD_CurrentVersionRun_69f2 {
  strings:
    $key_69f2 = { 3a 9d [2] 1e 93 [2] 35 bf [2] 1b 9d [2] 0f 86 [2] 00 9c [2] 1e 81 [2] 1c 80 [2] 07 86 [2] 1b 81 [2] 07 ae }

  condition:
    any of them
}