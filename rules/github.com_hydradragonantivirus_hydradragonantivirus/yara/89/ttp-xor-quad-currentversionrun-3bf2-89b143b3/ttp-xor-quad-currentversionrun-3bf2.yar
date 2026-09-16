rule TTP_XOR_QUAD_CurrentVersionRun_3bf2 {
  strings:
    $key_3bf2 = { 68 9d [2] 4c 93 [2] 67 bf [2] 49 9d [2] 5d 86 [2] 52 9c [2] 4c 81 [2] 4e 80 [2] 55 86 [2] 49 81 [2] 55 ae }

  condition:
    any of them
}