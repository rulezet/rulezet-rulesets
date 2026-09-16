rule TTP_XOR_QUAD_CurrentVersionRun_1417 {
  strings:
    $key_1417 = { 47 78 [2] 63 76 [2] 48 5a [2] 66 78 [2] 72 63 [2] 7d 79 [2] 63 64 [2] 61 65 [2] 7a 63 [2] 66 64 [2] 7a 4b }

  condition:
    any of them
}