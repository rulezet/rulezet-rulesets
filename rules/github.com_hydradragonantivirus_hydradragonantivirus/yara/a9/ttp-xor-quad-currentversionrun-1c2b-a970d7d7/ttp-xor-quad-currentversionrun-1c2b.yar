rule TTP_XOR_QUAD_CurrentVersionRun_1c2b {
  strings:
    $key_1c2b = { 4f 44 [2] 6b 4a [2] 40 66 [2] 6e 44 [2] 7a 5f [2] 75 45 [2] 6b 58 [2] 69 59 [2] 72 5f [2] 6e 58 [2] 72 77 }

  condition:
    any of them
}