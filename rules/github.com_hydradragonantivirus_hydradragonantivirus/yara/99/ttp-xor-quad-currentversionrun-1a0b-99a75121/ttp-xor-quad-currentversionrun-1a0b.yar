rule TTP_XOR_QUAD_CurrentVersionRun_1a0b {
  strings:
    $key_1a0b = { 49 64 [2] 6d 6a [2] 46 46 [2] 68 64 [2] 7c 7f [2] 73 65 [2] 6d 78 [2] 6f 79 [2] 74 7f [2] 68 78 [2] 74 57 }

  condition:
    any of them
}