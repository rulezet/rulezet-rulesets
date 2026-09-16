rule TTP_XOR_QUAD_CurrentVersionRun_3246 {
  strings:
    $key_3246 = { 61 29 [2] 45 27 [2] 6e 0b [2] 40 29 [2] 54 32 [2] 5b 28 [2] 45 35 [2] 47 34 [2] 5c 32 [2] 40 35 [2] 5c 1a }

  condition:
    any of them
}