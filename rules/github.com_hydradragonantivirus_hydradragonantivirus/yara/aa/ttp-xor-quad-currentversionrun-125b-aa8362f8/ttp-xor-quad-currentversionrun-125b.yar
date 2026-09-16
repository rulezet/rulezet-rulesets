rule TTP_XOR_QUAD_CurrentVersionRun_125b {
  strings:
    $key_125b = { 41 34 [2] 65 3a [2] 4e 16 [2] 60 34 [2] 74 2f [2] 7b 35 [2] 65 28 [2] 67 29 [2] 7c 2f [2] 60 28 [2] 7c 07 }

  condition:
    any of them
}