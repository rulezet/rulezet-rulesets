rule TTP_XOR_QUAD_CurrentVersionRun_1b17 {
  strings:
    $key_1b17 = { 48 78 [2] 6c 76 [2] 47 5a [2] 69 78 [2] 7d 63 [2] 72 79 [2] 6c 64 [2] 6e 65 [2] 75 63 [2] 69 64 [2] 75 4b }

  condition:
    any of them
}