rule TTP_XOR_QUAD_CurrentVersionRun_f5e1 {
  strings:
    $key_f5e1 = { a6 8e [2] 82 80 [2] a9 ac [2] 87 8e [2] 93 95 [2] 9c 8f [2] 82 92 [2] 80 93 [2] 9b 95 [2] 87 92 [2] 9b bd }

  condition:
    any of them
}