rule TTP_XOR_QUAD_CurrentVersionRun_03e1 {
  strings:
    $key_03e1 = { 50 8e [2] 74 80 [2] 5f ac [2] 71 8e [2] 65 95 [2] 6a 8f [2] 74 92 [2] 76 93 [2] 6d 95 [2] 71 92 [2] 6d bd }

  condition:
    any of them
}