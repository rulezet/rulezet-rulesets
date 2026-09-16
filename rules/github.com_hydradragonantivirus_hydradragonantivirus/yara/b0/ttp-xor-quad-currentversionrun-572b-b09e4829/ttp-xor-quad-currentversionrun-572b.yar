rule TTP_XOR_QUAD_CurrentVersionRun_572b {
  strings:
    $key_572b = { 04 44 [2] 20 4a [2] 0b 66 [2] 25 44 [2] 31 5f [2] 3e 45 [2] 20 58 [2] 22 59 [2] 39 5f [2] 25 58 [2] 39 77 }

  condition:
    any of them
}