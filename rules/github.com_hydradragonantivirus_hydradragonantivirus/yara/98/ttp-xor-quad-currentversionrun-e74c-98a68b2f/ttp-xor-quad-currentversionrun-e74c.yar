rule TTP_XOR_QUAD_CurrentVersionRun_e74c {
  strings:
    $key_e74c = { b4 23 [2] 90 2d [2] bb 01 [2] 95 23 [2] 81 38 [2] 8e 22 [2] 90 3f [2] 92 3e [2] 89 38 [2] 95 3f [2] 89 10 }

  condition:
    any of them
}