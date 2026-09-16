rule TTP_XOR_QUAD_CurrentVersionRun_08f2 {
  strings:
    $key_08f2 = { 5b 9d [2] 7f 93 [2] 54 bf [2] 7a 9d [2] 6e 86 [2] 61 9c [2] 7f 81 [2] 7d 80 [2] 66 86 [2] 7a 81 [2] 66 ae }

  condition:
    any of them
}