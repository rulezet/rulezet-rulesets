rule TTP_XOR_QUAD_CurrentVersionRun_74e1 {
  strings:
    $key_74e1 = { 27 8e [2] 03 80 [2] 28 ac [2] 06 8e [2] 12 95 [2] 1d 8f [2] 03 92 [2] 01 93 [2] 1a 95 [2] 06 92 [2] 1a bd }

  condition:
    any of them
}