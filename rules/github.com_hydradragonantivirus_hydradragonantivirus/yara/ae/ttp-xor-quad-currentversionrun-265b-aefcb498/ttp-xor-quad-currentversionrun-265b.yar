rule TTP_XOR_QUAD_CurrentVersionRun_265b {
  strings:
    $key_265b = { 75 34 [2] 51 3a [2] 7a 16 [2] 54 34 [2] 40 2f [2] 4f 35 [2] 51 28 [2] 53 29 [2] 48 2f [2] 54 28 [2] 48 07 }

  condition:
    any of them
}