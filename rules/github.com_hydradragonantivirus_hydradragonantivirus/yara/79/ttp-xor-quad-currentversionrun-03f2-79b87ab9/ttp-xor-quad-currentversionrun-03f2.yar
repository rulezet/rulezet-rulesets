rule TTP_XOR_QUAD_CurrentVersionRun_03f2 {
  strings:
    $key_03f2 = { 50 9d [2] 74 93 [2] 5f bf [2] 71 9d [2] 65 86 [2] 6a 9c [2] 74 81 [2] 76 80 [2] 6d 86 [2] 71 81 [2] 6d ae }

  condition:
    any of them
}