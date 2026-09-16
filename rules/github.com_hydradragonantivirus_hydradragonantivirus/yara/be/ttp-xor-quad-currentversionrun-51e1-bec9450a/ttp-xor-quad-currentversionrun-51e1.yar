rule TTP_XOR_QUAD_CurrentVersionRun_51e1 {
  strings:
    $key_51e1 = { 02 8e [2] 26 80 [2] 0d ac [2] 23 8e [2] 37 95 [2] 38 8f [2] 26 92 [2] 24 93 [2] 3f 95 [2] 23 92 [2] 3f bd }

  condition:
    any of them
}