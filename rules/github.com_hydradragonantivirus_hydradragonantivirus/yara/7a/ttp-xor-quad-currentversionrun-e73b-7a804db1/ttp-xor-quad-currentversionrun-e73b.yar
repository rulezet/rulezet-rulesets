rule TTP_XOR_QUAD_CurrentVersionRun_e73b {
  strings:
    $key_e73b = { b4 54 [2] 90 5a [2] bb 76 [2] 95 54 [2] 81 4f [2] 8e 55 [2] 90 48 [2] 92 49 [2] 89 4f [2] 95 48 [2] 89 67 }

  condition:
    any of them
}