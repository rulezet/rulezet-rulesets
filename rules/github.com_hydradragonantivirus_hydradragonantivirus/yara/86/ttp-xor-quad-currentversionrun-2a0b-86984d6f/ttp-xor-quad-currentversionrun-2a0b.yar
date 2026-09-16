rule TTP_XOR_QUAD_CurrentVersionRun_2a0b {
  strings:
    $key_2a0b = { 79 64 [2] 5d 6a [2] 76 46 [2] 58 64 [2] 4c 7f [2] 43 65 [2] 5d 78 [2] 5f 79 [2] 44 7f [2] 58 78 [2] 44 57 }

  condition:
    any of them
}