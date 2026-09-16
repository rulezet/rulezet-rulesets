rule TTP_XOR_QUAD_CurrentVersionRun_1517 {
  strings:
    $key_1517 = { 46 78 [2] 62 76 [2] 49 5a [2] 67 78 [2] 73 63 [2] 7c 79 [2] 62 64 [2] 60 65 [2] 7b 63 [2] 67 64 [2] 7b 4b }

  condition:
    any of them
}