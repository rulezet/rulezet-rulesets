rule TTP_XOR_QUAD_CurrentVersionRun_7517 {
  strings:
    $key_7517 = { 26 78 [2] 02 76 [2] 29 5a [2] 07 78 [2] 13 63 [2] 1c 79 [2] 02 64 [2] 00 65 [2] 1b 63 [2] 07 64 [2] 1b 4b }

  condition:
    any of them
}