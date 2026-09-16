rule TTP_XOR_QUAD_CurrentVersionRun_0257 {
  strings:
    $key_0257 = { 51 38 [2] 75 36 [2] 5e 1a [2] 70 38 [2] 64 23 [2] 6b 39 [2] 75 24 [2] 77 25 [2] 6c 23 [2] 70 24 [2] 6c 0b }

  condition:
    any of them
}