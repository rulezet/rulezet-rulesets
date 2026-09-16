rule TTP_XOR_QUAD_CurrentVersionRun_26e1 {
  strings:
    $key_26e1 = { 75 8e [2] 51 80 [2] 7a ac [2] 54 8e [2] 40 95 [2] 4f 8f [2] 51 92 [2] 53 93 [2] 48 95 [2] 54 92 [2] 48 bd }

  condition:
    any of them
}