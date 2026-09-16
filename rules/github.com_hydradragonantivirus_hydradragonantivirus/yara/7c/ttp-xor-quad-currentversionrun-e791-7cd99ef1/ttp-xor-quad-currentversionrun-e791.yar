rule TTP_XOR_QUAD_CurrentVersionRun_e791 {
  strings:
    $key_e791 = { b4 fe [2] 90 f0 [2] bb dc [2] 95 fe [2] 81 e5 [2] 8e ff [2] 90 e2 [2] 92 e3 [2] 89 e5 [2] 95 e2 [2] 89 cd }

  condition:
    any of them
}