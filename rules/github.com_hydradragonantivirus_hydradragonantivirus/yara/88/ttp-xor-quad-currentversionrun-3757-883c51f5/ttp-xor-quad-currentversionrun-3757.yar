rule TTP_XOR_QUAD_CurrentVersionRun_3757 {
  strings:
    $key_3757 = { 64 38 [2] 40 36 [2] 6b 1a [2] 45 38 [2] 51 23 [2] 5e 39 [2] 40 24 [2] 42 25 [2] 59 23 [2] 45 24 [2] 59 0b }

  condition:
    any of them
}