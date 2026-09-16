rule TTP_XOR_QUAD_CurrentVersionRun_781b {
  strings:
    $key_781b = { 2b 74 [2] 0f 7a [2] 24 56 [2] 0a 74 [2] 1e 6f [2] 11 75 [2] 0f 68 [2] 0d 69 [2] 16 6f [2] 0a 68 [2] 16 47 }

  condition:
    any of them
}