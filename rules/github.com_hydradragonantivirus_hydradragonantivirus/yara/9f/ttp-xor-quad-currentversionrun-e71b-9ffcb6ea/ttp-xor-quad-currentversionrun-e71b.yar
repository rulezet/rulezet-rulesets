rule TTP_XOR_QUAD_CurrentVersionRun_e71b {
  strings:
    $key_e71b = { b4 74 [2] 90 7a [2] bb 56 [2] 95 74 [2] 81 6f [2] 8e 75 [2] 90 68 [2] 92 69 [2] 89 6f [2] 95 68 [2] 89 47 }

  condition:
    any of them
}