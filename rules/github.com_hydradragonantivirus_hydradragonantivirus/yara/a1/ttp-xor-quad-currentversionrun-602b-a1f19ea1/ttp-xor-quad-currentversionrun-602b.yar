rule TTP_XOR_QUAD_CurrentVersionRun_602b {
  strings:
    $key_602b = { 33 44 [2] 17 4a [2] 3c 66 [2] 12 44 [2] 06 5f [2] 09 45 [2] 17 58 [2] 15 59 [2] 0e 5f [2] 12 58 [2] 0e 77 }

  condition:
    any of them
}