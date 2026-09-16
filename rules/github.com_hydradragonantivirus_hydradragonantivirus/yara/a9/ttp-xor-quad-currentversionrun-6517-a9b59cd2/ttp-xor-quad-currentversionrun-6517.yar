rule TTP_XOR_QUAD_CurrentVersionRun_6517 {
  strings:
    $key_6517 = { 36 78 [2] 12 76 [2] 39 5a [2] 17 78 [2] 03 63 [2] 0c 79 [2] 12 64 [2] 10 65 [2] 0b 63 [2] 17 64 [2] 0b 4b }

  condition:
    any of them
}