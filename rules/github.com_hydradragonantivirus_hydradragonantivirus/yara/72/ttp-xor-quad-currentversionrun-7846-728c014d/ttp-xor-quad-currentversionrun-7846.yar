rule TTP_XOR_QUAD_CurrentVersionRun_7846 {
  strings:
    $key_7846 = { 2b 29 [2] 0f 27 [2] 24 0b [2] 0a 29 [2] 1e 32 [2] 11 28 [2] 0f 35 [2] 0d 34 [2] 16 32 [2] 0a 35 [2] 16 1a }

  condition:
    any of them
}