rule TTP_XOR_QUAD_CurrentVersionRun_0237 {
  strings:
    $key_0237 = { 51 58 [2] 75 56 [2] 5e 7a [2] 70 58 [2] 64 43 [2] 6b 59 [2] 75 44 [2] 77 45 [2] 6c 43 [2] 70 44 [2] 6c 6b }

  condition:
    any of them
}