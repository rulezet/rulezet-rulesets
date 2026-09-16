rule TTP_XOR_QUAD_CurrentVersionRun_0f5b {
  strings:
    $key_0f5b = { 5c 34 [2] 78 3a [2] 53 16 [2] 7d 34 [2] 69 2f [2] 66 35 [2] 78 28 [2] 7a 29 [2] 61 2f [2] 7d 28 [2] 61 07 }

  condition:
    any of them
}