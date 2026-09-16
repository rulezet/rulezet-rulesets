rule TTP_XOR_QUAD_CurrentVersionRun_50f2 {
  strings:
    $key_50f2 = { 03 9d [2] 27 93 [2] 0c bf [2] 22 9d [2] 36 86 [2] 39 9c [2] 27 81 [2] 25 80 [2] 3e 86 [2] 22 81 [2] 3e ae }

  condition:
    any of them
}