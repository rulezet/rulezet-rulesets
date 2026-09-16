rule TTP_XOR_QUAD_CurrentVersionRun_1b2b {
  strings:
    $key_1b2b = { 48 44 [2] 6c 4a [2] 47 66 [2] 69 44 [2] 7d 5f [2] 72 45 [2] 6c 58 [2] 6e 59 [2] 75 5f [2] 69 58 [2] 75 77 }

  condition:
    any of them
}