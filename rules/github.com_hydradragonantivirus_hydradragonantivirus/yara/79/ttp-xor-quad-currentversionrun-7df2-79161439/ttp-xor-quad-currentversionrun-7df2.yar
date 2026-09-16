rule TTP_XOR_QUAD_CurrentVersionRun_7df2 {
  strings:
    $key_7df2 = { 2e 9d [2] 0a 93 [2] 21 bf [2] 0f 9d [2] 1b 86 [2] 14 9c [2] 0a 81 [2] 08 80 [2] 13 86 [2] 0f 81 [2] 13 ae }

  condition:
    any of them
}