rule TTP_XOR_QUAD_CurrentVersionRun_245b {
  strings:
    $key_245b = { 77 34 [2] 53 3a [2] 78 16 [2] 56 34 [2] 42 2f [2] 4d 35 [2] 53 28 [2] 51 29 [2] 4a 2f [2] 56 28 [2] 4a 07 }

  condition:
    any of them
}