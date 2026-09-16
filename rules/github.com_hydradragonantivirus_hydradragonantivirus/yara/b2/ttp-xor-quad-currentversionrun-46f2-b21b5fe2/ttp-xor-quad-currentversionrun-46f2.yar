rule TTP_XOR_QUAD_CurrentVersionRun_46f2 {
  strings:
    $key_46f2 = { 15 9d [2] 31 93 [2] 1a bf [2] 34 9d [2] 20 86 [2] 2f 9c [2] 31 81 [2] 33 80 [2] 28 86 [2] 34 81 [2] 28 ae }

  condition:
    any of them
}