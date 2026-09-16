rule TTP_XOR_QUAD_CurrentVersionRun_575b {
  strings:
    $key_575b = { 04 34 [2] 20 3a [2] 0b 16 [2] 25 34 [2] 31 2f [2] 3e 35 [2] 20 28 [2] 22 29 [2] 39 2f [2] 25 28 [2] 39 07 }

  condition:
    any of them
}