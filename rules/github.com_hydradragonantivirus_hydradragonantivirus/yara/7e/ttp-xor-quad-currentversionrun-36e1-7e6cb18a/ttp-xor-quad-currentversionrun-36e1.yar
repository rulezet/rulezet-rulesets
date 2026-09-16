rule TTP_XOR_QUAD_CurrentVersionRun_36e1 {
  strings:
    $key_36e1 = { 65 8e [2] 41 80 [2] 6a ac [2] 44 8e [2] 50 95 [2] 5f 8f [2] 41 92 [2] 43 93 [2] 58 95 [2] 44 92 [2] 58 bd }

  condition:
    any of them
}