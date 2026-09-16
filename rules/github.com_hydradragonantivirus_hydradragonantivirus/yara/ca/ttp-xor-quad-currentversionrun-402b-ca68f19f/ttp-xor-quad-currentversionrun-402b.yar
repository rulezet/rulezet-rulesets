rule TTP_XOR_QUAD_CurrentVersionRun_402b {
  strings:
    $key_402b = { 13 44 [2] 37 4a [2] 1c 66 [2] 32 44 [2] 26 5f [2] 29 45 [2] 37 58 [2] 35 59 [2] 2e 5f [2] 32 58 [2] 2e 77 }

  condition:
    any of them
}