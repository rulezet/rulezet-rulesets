rule TTP_XOR_QUAD_CurrentVersionRun_155b {
  strings:
    $key_155b = { 46 34 [2] 62 3a [2] 49 16 [2] 67 34 [2] 73 2f [2] 7c 35 [2] 62 28 [2] 60 29 [2] 7b 2f [2] 67 28 [2] 7b 07 }

  condition:
    any of them
}