rule TTP_XOR_QUAD_CurrentVersionRun_0bf2 {
  strings:
    $key_0bf2 = { 58 9d [2] 7c 93 [2] 57 bf [2] 79 9d [2] 6d 86 [2] 62 9c [2] 7c 81 [2] 7e 80 [2] 65 86 [2] 79 81 [2] 65 ae }

  condition:
    any of them
}