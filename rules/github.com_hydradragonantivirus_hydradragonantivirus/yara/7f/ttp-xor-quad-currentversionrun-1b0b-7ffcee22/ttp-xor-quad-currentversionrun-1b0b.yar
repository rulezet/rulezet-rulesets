rule TTP_XOR_QUAD_CurrentVersionRun_1b0b {
  strings:
    $key_1b0b = { 48 64 [2] 6c 6a [2] 47 46 [2] 69 64 [2] 7d 7f [2] 72 65 [2] 6c 78 [2] 6e 79 [2] 75 7f [2] 69 78 [2] 75 57 }

  condition:
    any of them
}