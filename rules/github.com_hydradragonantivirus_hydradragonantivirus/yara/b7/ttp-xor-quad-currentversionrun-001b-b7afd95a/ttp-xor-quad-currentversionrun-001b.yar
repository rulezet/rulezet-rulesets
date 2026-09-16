rule TTP_XOR_QUAD_CurrentVersionRun_001b {
  strings:
    $key_001b = { 53 74 [2] 77 7a [2] 5c 56 [2] 72 74 [2] 66 6f [2] 69 75 [2] 77 68 [2] 75 69 [2] 6e 6f [2] 72 68 [2] 6e 47 }

  condition:
    any of them
}