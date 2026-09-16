rule TTP_XOR_QUAD_CurrentVersionRun_04e1 {
  strings:
    $key_04e1 = { 57 8e [2] 73 80 [2] 58 ac [2] 76 8e [2] 62 95 [2] 6d 8f [2] 73 92 [2] 71 93 [2] 6a 95 [2] 76 92 [2] 6a bd }

  condition:
    any of them
}