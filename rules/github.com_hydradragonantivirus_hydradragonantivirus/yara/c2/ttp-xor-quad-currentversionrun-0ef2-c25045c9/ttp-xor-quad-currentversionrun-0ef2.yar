rule TTP_XOR_QUAD_CurrentVersionRun_0ef2 {
  strings:
    $key_0ef2 = { 5d 9d [2] 79 93 [2] 52 bf [2] 7c 9d [2] 68 86 [2] 67 9c [2] 79 81 [2] 7b 80 [2] 60 86 [2] 7c 81 [2] 60 ae }

  condition:
    any of them
}