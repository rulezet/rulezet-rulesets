rule TTP_XOR_QUAD_CurrentVersionRun_e71d {
  strings:
    $key_e71d = { b4 72 [2] 90 7c [2] bb 50 [2] 95 72 [2] 81 69 [2] 8e 73 [2] 90 6e [2] 92 6f [2] 89 69 [2] 95 6e [2] 89 41 }

  condition:
    any of them
}