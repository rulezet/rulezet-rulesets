rule TTP_XOR_QUAD_CurrentVersionRun_4bf2 {
  strings:
    $key_4bf2 = { 18 9d [2] 3c 93 [2] 17 bf [2] 39 9d [2] 2d 86 [2] 22 9c [2] 3c 81 [2] 3e 80 [2] 25 86 [2] 39 81 [2] 25 ae }

  condition:
    any of them
}