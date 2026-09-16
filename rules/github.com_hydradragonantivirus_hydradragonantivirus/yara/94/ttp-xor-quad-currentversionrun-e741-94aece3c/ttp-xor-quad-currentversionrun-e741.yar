rule TTP_XOR_QUAD_CurrentVersionRun_e741 {
  strings:
    $key_e741 = { b4 2e [2] 90 20 [2] bb 0c [2] 95 2e [2] 81 35 [2] 8e 2f [2] 90 32 [2] 92 33 [2] 89 35 [2] 95 32 [2] 89 1d }

  condition:
    any of them
}