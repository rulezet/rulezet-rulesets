rule TTP_XOR_QUAD_CurrentVersionRun_4df2 {
  strings:
    $key_4df2 = { 1e 9d [2] 3a 93 [2] 11 bf [2] 3f 9d [2] 2b 86 [2] 24 9c [2] 3a 81 [2] 38 80 [2] 23 86 [2] 3f 81 [2] 23 ae }

  condition:
    any of them
}