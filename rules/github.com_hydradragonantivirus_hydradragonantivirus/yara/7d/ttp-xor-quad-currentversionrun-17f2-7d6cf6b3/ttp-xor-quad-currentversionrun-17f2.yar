rule TTP_XOR_QUAD_CurrentVersionRun_17f2 {
  strings:
    $key_17f2 = { 44 9d [2] 60 93 [2] 4b bf [2] 65 9d [2] 71 86 [2] 7e 9c [2] 60 81 [2] 62 80 [2] 79 86 [2] 65 81 [2] 79 ae }

  condition:
    any of them
}