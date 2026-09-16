rule TTP_XOR_QUAD_CurrentVersionRun_195b {
  strings:
    $key_195b = { 4a 34 [2] 6e 3a [2] 45 16 [2] 6b 34 [2] 7f 2f [2] 70 35 [2] 6e 28 [2] 6c 29 [2] 77 2f [2] 6b 28 [2] 77 07 }

  condition:
    any of them
}