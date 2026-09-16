rule TTP_XOR_QUAD_CurrentVersionRun_64e1 {
  strings:
    $key_64e1 = { 37 8e [2] 13 80 [2] 38 ac [2] 16 8e [2] 02 95 [2] 0d 8f [2] 13 92 [2] 11 93 [2] 0a 95 [2] 16 92 [2] 0a bd }

  condition:
    any of them
}