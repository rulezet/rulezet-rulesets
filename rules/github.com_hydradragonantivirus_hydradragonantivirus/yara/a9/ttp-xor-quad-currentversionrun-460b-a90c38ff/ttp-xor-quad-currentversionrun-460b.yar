rule TTP_XOR_QUAD_CurrentVersionRun_460b {
  strings:
    $key_460b = { 15 64 [2] 31 6a [2] 1a 46 [2] 34 64 [2] 20 7f [2] 2f 65 [2] 31 78 [2] 33 79 [2] 28 7f [2] 34 78 [2] 28 57 }

  condition:
    any of them
}