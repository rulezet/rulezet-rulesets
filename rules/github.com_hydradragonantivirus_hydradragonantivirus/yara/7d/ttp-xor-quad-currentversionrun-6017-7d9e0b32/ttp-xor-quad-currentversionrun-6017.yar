rule TTP_XOR_QUAD_CurrentVersionRun_6017 {
  strings:
    $key_6017 = { 33 78 [2] 17 76 [2] 3c 5a [2] 12 78 [2] 06 63 [2] 09 79 [2] 17 64 [2] 15 65 [2] 0e 63 [2] 12 64 [2] 0e 4b }

  condition:
    any of them
}