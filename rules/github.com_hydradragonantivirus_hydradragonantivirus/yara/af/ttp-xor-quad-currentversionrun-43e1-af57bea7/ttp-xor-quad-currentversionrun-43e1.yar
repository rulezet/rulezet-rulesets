rule TTP_XOR_QUAD_CurrentVersionRun_43e1 {
  strings:
    $key_43e1 = { 10 8e [2] 34 80 [2] 1f ac [2] 31 8e [2] 25 95 [2] 2a 8f [2] 34 92 [2] 36 93 [2] 2d 95 [2] 31 92 [2] 2d bd }

  condition:
    any of them
}