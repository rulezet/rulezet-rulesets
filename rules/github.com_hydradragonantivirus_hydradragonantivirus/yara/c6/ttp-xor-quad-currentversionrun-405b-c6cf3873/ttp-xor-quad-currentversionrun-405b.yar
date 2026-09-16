rule TTP_XOR_QUAD_CurrentVersionRun_405b {
  strings:
    $key_405b = { 13 34 [2] 37 3a [2] 1c 16 [2] 32 34 [2] 26 2f [2] 29 35 [2] 37 28 [2] 35 29 [2] 2e 2f [2] 32 28 [2] 2e 07 }

  condition:
    any of them
}