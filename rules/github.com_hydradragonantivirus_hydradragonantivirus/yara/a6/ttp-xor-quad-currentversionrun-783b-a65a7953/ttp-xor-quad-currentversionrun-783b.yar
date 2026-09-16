rule TTP_XOR_QUAD_CurrentVersionRun_783b {
  strings:
    $key_783b = { 2b 54 [2] 0f 5a [2] 24 76 [2] 0a 54 [2] 1e 4f [2] 11 55 [2] 0f 48 [2] 0d 49 [2] 16 4f [2] 0a 48 [2] 16 67 }

  condition:
    any of them
}