rule TTP_XOR_QUAD_CurrentVersionRun_671b {
  strings:
    $key_671b = { 34 74 [2] 10 7a [2] 3b 56 [2] 15 74 [2] 01 6f [2] 0e 75 [2] 10 68 [2] 12 69 [2] 09 6f [2] 15 68 [2] 09 47 }

  condition:
    any of them
}