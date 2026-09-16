rule TTP_XOR_QUAD_CurrentVersionRun_785b {
  strings:
    $key_785b = { 2b 34 [2] 0f 3a [2] 24 16 [2] 0a 34 [2] 1e 2f [2] 11 35 [2] 0f 28 [2] 0d 29 [2] 16 2f [2] 0a 28 [2] 16 07 }

  condition:
    any of them
}