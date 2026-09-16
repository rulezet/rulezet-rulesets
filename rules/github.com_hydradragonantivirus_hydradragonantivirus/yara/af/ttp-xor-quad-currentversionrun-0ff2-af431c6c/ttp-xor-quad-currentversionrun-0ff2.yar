rule TTP_XOR_QUAD_CurrentVersionRun_0ff2 {
  strings:
    $key_0ff2 = { 5c 9d [2] 78 93 [2] 53 bf [2] 7d 9d [2] 69 86 [2] 66 9c [2] 78 81 [2] 7a 80 [2] 61 86 [2] 7d 81 [2] 61 ae }

  condition:
    any of them
}