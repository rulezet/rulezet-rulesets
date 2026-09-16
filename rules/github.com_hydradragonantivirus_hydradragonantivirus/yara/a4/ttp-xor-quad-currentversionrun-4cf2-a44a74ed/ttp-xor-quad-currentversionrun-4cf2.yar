rule TTP_XOR_QUAD_CurrentVersionRun_4cf2 {
  strings:
    $key_4cf2 = { 1f 9d [2] 3b 93 [2] 10 bf [2] 3e 9d [2] 2a 86 [2] 25 9c [2] 3b 81 [2] 39 80 [2] 22 86 [2] 3e 81 [2] 22 ae }

  condition:
    any of them
}