rule TTP_XOR_QUAD_CurrentVersionRun_36f2 {
  strings:
    $key_36f2 = { 65 9d [2] 41 93 [2] 6a bf [2] 44 9d [2] 50 86 [2] 5f 9c [2] 41 81 [2] 43 80 [2] 58 86 [2] 44 81 [2] 58 ae }

  condition:
    any of them
}