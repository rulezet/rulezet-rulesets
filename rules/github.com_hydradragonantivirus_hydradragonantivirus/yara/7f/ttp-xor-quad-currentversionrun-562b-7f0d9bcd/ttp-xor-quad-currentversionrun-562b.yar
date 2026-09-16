rule TTP_XOR_QUAD_CurrentVersionRun_562b {
  strings:
    $key_562b = { 05 44 [2] 21 4a [2] 0a 66 [2] 24 44 [2] 30 5f [2] 3f 45 [2] 21 58 [2] 23 59 [2] 38 5f [2] 24 58 [2] 38 77 }

  condition:
    any of them
}