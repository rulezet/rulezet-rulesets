rule TTP_XOR_QUAD_CurrentVersionRun_2e2b {
  strings:
    $key_2e2b = { 7d 44 [2] 59 4a [2] 72 66 [2] 5c 44 [2] 48 5f [2] 47 45 [2] 59 58 [2] 5b 59 [2] 40 5f [2] 5c 58 [2] 40 77 }

  condition:
    any of them
}