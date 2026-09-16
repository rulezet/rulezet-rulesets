rule TTP_XOR_QUAD_CurrentVersionRun_f1e1 {
  strings:
    $key_f1e1 = { a2 8e [2] 86 80 [2] ad ac [2] 83 8e [2] 97 95 [2] 98 8f [2] 86 92 [2] 84 93 [2] 9f 95 [2] 83 92 [2] 9f bd }

  condition:
    any of them
}