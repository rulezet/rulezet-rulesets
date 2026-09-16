rule TTP_XOR_QUAD_CurrentVersionRun_40f2 {
  strings:
    $key_40f2 = { 13 9d [2] 37 93 [2] 1c bf [2] 32 9d [2] 26 86 [2] 29 9c [2] 37 81 [2] 35 80 [2] 2e 86 [2] 32 81 [2] 2e ae }

  condition:
    any of them
}