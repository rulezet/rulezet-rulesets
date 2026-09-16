rule TTP_XOR_QUAD_CurrentVersionRun_7806 {
  strings:
    $key_7806 = { 2b 69 [2] 0f 67 [2] 24 4b [2] 0a 69 [2] 1e 72 [2] 11 68 [2] 0f 75 [2] 0d 74 [2] 16 72 [2] 0a 75 [2] 16 5a }

  condition:
    any of them
}