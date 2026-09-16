rule TTP_XOR_QUAD_CurrentVersionRun_675b {
  strings:
    $key_675b = { 34 34 [2] 10 3a [2] 3b 16 [2] 15 34 [2] 01 2f [2] 0e 35 [2] 10 28 [2] 12 29 [2] 09 2f [2] 15 28 [2] 09 07 }

  condition:
    any of them
}