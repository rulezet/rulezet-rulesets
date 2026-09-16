rule TTP_XOR_QUAD_CurrentVersionRun_465b {
  strings:
    $key_465b = { 15 34 [2] 31 3a [2] 1a 16 [2] 34 34 [2] 20 2f [2] 2f 35 [2] 31 28 [2] 33 29 [2] 28 2f [2] 34 28 [2] 28 07 }

  condition:
    any of them
}