rule TTP_XOR_QUAD_CurrentVersionRun_f7e1 {
  strings:
    $key_f7e1 = { a4 8e [2] 80 80 [2] ab ac [2] 85 8e [2] 91 95 [2] 9e 8f [2] 80 92 [2] 82 93 [2] 99 95 [2] 85 92 [2] 99 bd }

  condition:
    any of them
}