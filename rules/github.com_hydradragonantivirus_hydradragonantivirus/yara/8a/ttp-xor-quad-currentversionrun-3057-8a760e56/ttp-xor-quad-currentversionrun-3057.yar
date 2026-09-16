rule TTP_XOR_QUAD_CurrentVersionRun_3057 {
  strings:
    $key_3057 = { 63 38 [2] 47 36 [2] 6c 1a [2] 42 38 [2] 56 23 [2] 59 39 [2] 47 24 [2] 45 25 [2] 5e 23 [2] 42 24 [2] 5e 0b }

  condition:
    any of them
}