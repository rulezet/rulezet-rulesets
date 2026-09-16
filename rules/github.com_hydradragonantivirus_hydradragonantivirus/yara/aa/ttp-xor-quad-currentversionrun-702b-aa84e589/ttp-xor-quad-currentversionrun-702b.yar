rule TTP_XOR_QUAD_CurrentVersionRun_702b {
  strings:
    $key_702b = { 23 44 [2] 07 4a [2] 2c 66 [2] 02 44 [2] 16 5f [2] 19 45 [2] 07 58 [2] 05 59 [2] 1e 5f [2] 02 58 [2] 1e 77 }

  condition:
    any of them
}