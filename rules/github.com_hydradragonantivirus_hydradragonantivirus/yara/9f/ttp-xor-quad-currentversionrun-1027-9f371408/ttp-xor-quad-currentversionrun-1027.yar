rule TTP_XOR_QUAD_CurrentVersionRun_1027 {
  strings:
    $key_1027 = { 43 48 [2] 67 46 [2] 4c 6a [2] 62 48 [2] 76 53 [2] 79 49 [2] 67 54 [2] 65 55 [2] 7e 53 [2] 62 54 [2] 7e 7b }

  condition:
    any of them
}