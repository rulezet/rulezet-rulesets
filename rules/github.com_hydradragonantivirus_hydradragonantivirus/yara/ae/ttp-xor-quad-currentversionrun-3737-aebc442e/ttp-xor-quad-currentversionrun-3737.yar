rule TTP_XOR_QUAD_CurrentVersionRun_3737 {
  strings:
    $key_3737 = { 64 58 [2] 40 56 [2] 6b 7a [2] 45 58 [2] 51 43 [2] 5e 59 [2] 40 44 [2] 42 45 [2] 59 43 [2] 45 44 [2] 59 6b }

  condition:
    any of them
}