rule TTP_XOR_QUAD_CurrentVersionRun_13e1 {
  strings:
    $key_13e1 = { 40 8e [2] 64 80 [2] 4f ac [2] 61 8e [2] 75 95 [2] 7a 8f [2] 64 92 [2] 66 93 [2] 7d 95 [2] 61 92 [2] 7d bd }

  condition:
    any of them
}