rule TTP_XOR_QUAD_CurrentVersionRun_007b {
  strings:
    $key_007b = { 53 14 [2] 77 1a [2] 5c 36 [2] 72 14 [2] 66 0f [2] 69 15 [2] 77 08 [2] 75 09 [2] 6e 0f [2] 72 08 [2] 6e 27 }

  condition:
    any of them
}