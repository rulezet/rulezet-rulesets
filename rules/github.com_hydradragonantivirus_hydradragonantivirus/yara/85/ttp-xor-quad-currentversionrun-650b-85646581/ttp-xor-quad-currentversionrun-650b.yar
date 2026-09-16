rule TTP_XOR_QUAD_CurrentVersionRun_650b {
  strings:
    $key_650b = { 36 64 [2] 12 6a [2] 39 46 [2] 17 64 [2] 03 7f [2] 0c 65 [2] 12 78 [2] 10 79 [2] 0b 7f [2] 17 78 [2] 0b 57 }

  condition:
    any of them
}