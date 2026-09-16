rule TTP_XOR_QUAD_CurrentVersionRun_f4e1 {
  strings:
    $key_f4e1 = { a7 8e [2] 83 80 [2] a8 ac [2] 86 8e [2] 92 95 [2] 9d 8f [2] 83 92 [2] 81 93 [2] 9a 95 [2] 86 92 [2] 9a bd }

  condition:
    any of them
}