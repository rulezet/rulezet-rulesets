rule TTP_XOR_QUAD_CurrentVersionRun_782b {
  strings:
    $key_782b = { 2b 44 [2] 0f 4a [2] 24 66 [2] 0a 44 [2] 1e 5f [2] 11 45 [2] 0f 58 [2] 0d 59 [2] 16 5f [2] 0a 58 [2] 16 77 }

  condition:
    any of them
}