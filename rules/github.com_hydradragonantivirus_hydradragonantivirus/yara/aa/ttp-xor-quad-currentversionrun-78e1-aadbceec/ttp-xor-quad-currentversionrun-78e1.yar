rule TTP_XOR_QUAD_CurrentVersionRun_78e1 {
  strings:
    $key_78e1 = { 2b 8e [2] 0f 80 [2] 24 ac [2] 0a 8e [2] 1e 95 [2] 11 8f [2] 0f 92 [2] 0d 93 [2] 16 95 [2] 0a 92 [2] 16 bd }

  condition:
    any of them
}