rule TTP_XOR_QUAD_CurrentVersionRun_1c17 {
  strings:
    $key_1c17 = { 4f 78 [2] 6b 76 [2] 40 5a [2] 6e 78 [2] 7a 63 [2] 75 79 [2] 6b 64 [2] 69 65 [2] 72 63 [2] 6e 64 [2] 72 4b }

  condition:
    any of them
}