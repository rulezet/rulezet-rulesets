rule TTP_XOR_QUAD_CurrentVersionRun_070b {
  strings:
    $key_070b = { 54 64 [2] 70 6a [2] 5b 46 [2] 75 64 [2] 61 7f [2] 6e 65 [2] 70 78 [2] 72 79 [2] 69 7f [2] 75 78 [2] 69 57 }

  condition:
    any of them
}