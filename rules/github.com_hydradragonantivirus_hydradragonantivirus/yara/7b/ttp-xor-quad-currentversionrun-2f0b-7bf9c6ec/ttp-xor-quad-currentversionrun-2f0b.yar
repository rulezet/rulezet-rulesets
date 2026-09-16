rule TTP_XOR_QUAD_CurrentVersionRun_2f0b {
  strings:
    $key_2f0b = { 7c 64 [2] 58 6a [2] 73 46 [2] 5d 64 [2] 49 7f [2] 46 65 [2] 58 78 [2] 5a 79 [2] 41 7f [2] 5d 78 [2] 41 57 }

  condition:
    any of them
}