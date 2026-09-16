rule TTP_XOR_QUAD_CurrentVersionRun_e771 {
  strings:
    $key_e771 = { b4 1e [2] 90 10 [2] bb 3c [2] 95 1e [2] 81 05 [2] 8e 1f [2] 90 02 [2] 92 03 [2] 89 05 [2] 95 02 [2] 89 2d }

  condition:
    any of them
}