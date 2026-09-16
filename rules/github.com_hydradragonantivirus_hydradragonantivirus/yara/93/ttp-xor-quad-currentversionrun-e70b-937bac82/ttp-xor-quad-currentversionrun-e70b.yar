rule TTP_XOR_QUAD_CurrentVersionRun_e70b {
  strings:
    $key_e70b = { b4 64 [2] 90 6a [2] bb 46 [2] 95 64 [2] 81 7f [2] 8e 65 [2] 90 78 [2] 92 79 [2] 89 7f [2] 95 78 [2] 89 57 }

  condition:
    any of them
}