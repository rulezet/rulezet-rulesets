rule TTP_XOR_QUAD_CurrentVersionRun_e74a {
  strings:
    $key_e74a = { b4 25 [2] 90 2b [2] bb 07 [2] 95 25 [2] 81 3e [2] 8e 24 [2] 90 39 [2] 92 38 [2] 89 3e [2] 95 39 [2] 89 16 }

  condition:
    any of them
}