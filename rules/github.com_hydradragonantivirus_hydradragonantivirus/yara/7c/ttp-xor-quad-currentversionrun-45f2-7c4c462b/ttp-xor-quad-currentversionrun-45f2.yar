rule TTP_XOR_QUAD_CurrentVersionRun_45f2 {
  strings:
    $key_45f2 = { 16 9d [2] 32 93 [2] 19 bf [2] 37 9d [2] 23 86 [2] 2c 9c [2] 32 81 [2] 30 80 [2] 2b 86 [2] 37 81 [2] 2b ae }

  condition:
    any of them
}