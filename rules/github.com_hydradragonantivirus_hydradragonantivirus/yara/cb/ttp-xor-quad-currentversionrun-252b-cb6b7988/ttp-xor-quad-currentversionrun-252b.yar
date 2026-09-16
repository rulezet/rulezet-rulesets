rule TTP_XOR_QUAD_CurrentVersionRun_252b {
  strings:
    $key_252b = { 76 44 [2] 52 4a [2] 79 66 [2] 57 44 [2] 43 5f [2] 4c 45 [2] 52 58 [2] 50 59 [2] 4b 5f [2] 57 58 [2] 4b 77 }

  condition:
    any of them
}