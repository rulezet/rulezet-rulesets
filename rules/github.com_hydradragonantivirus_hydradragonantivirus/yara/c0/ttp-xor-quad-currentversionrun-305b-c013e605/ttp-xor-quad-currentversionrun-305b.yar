rule TTP_XOR_QUAD_CurrentVersionRun_305b {
  strings:
    $key_305b = { 63 34 [2] 47 3a [2] 6c 16 [2] 42 34 [2] 56 2f [2] 59 35 [2] 47 28 [2] 45 29 [2] 5e 2f [2] 42 28 [2] 5e 07 }

  condition:
    any of them
}