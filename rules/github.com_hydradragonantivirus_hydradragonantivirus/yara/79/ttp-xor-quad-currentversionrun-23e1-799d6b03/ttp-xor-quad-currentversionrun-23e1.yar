rule TTP_XOR_QUAD_CurrentVersionRun_23e1 {
  strings:
    $key_23e1 = { 70 8e [2] 54 80 [2] 7f ac [2] 51 8e [2] 45 95 [2] 4a 8f [2] 54 92 [2] 56 93 [2] 4d 95 [2] 51 92 [2] 4d bd }

  condition:
    any of them
}