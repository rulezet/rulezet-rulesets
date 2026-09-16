rule TTP_XOR_QUAD_CurrentVersionRun_e72b {
  strings:
    $key_e72b = { b4 44 [2] 90 4a [2] bb 66 [2] 95 44 [2] 81 5f [2] 8e 45 [2] 90 58 [2] 92 59 [2] 89 5f [2] 95 58 [2] 89 77 }

  condition:
    any of them
}