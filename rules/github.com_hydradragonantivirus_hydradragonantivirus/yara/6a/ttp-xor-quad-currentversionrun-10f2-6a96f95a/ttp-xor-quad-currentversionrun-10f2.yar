rule TTP_XOR_QUAD_CurrentVersionRun_10f2 {
  strings:
    $key_10f2 = { 43 9d [2] 67 93 [2] 4c bf [2] 62 9d [2] 76 86 [2] 79 9c [2] 67 81 [2] 65 80 [2] 7e 86 [2] 62 81 [2] 7e ae }

  condition:
    any of them
}