rule TTP_XOR_QUAD_CurrentVersionRun_72f2 {
  strings:
    $key_72f2 = { 21 9d [2] 05 93 [2] 2e bf [2] 00 9d [2] 14 86 [2] 1b 9c [2] 05 81 [2] 07 80 [2] 1c 86 [2] 00 81 [2] 1c ae }

  condition:
    any of them
}