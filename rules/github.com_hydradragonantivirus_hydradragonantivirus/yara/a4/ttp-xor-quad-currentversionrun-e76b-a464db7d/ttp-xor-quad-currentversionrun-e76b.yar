rule TTP_XOR_QUAD_CurrentVersionRun_e76b {
  strings:
    $key_e76b = { b4 04 [2] 90 0a [2] bb 26 [2] 95 04 [2] 81 1f [2] 8e 05 [2] 90 18 [2] 92 19 [2] 89 1f [2] 95 18 [2] 89 37 }

  condition:
    any of them
}