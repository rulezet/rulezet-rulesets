rule TTP_XOR_QUAD_CurrentVersionRun_6df2 {
  strings:
    $key_6df2 = { 3e 9d [2] 1a 93 [2] 31 bf [2] 1f 9d [2] 0b 86 [2] 04 9c [2] 1a 81 [2] 18 80 [2] 03 86 [2] 1f 81 [2] 03 ae }

  condition:
    any of them
}