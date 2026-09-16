rule TTP_XOR_QUAD_CurrentVersionRun_375b {
  strings:
    $key_375b = { 64 34 [2] 40 3a [2] 6b 16 [2] 45 34 [2] 51 2f [2] 5e 35 [2] 40 28 [2] 42 29 [2] 59 2f [2] 45 28 [2] 59 07 }

  condition:
    any of them
}