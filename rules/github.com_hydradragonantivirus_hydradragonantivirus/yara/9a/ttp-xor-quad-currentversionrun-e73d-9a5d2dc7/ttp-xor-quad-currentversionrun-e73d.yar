rule TTP_XOR_QUAD_CurrentVersionRun_e73d {
  strings:
    $key_e73d = { b4 52 [2] 90 5c [2] bb 70 [2] 95 52 [2] 81 49 [2] 8e 53 [2] 90 4e [2] 92 4f [2] 89 49 [2] 95 4e [2] 89 61 }

  condition:
    any of them
}