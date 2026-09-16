rule TTP_XOR_QUAD_CurrentVersionRun_355b {
  strings:
    $key_355b = { 66 34 [2] 42 3a [2] 69 16 [2] 47 34 [2] 53 2f [2] 5c 35 [2] 42 28 [2] 40 29 [2] 5b 2f [2] 47 28 [2] 5b 07 }

  condition:
    any of them
}