rule TTP_XOR_QUAD_CurrentVersionRun_f66b {
  strings:
    $key_f66b = { a5 04 [2] 81 0a [2] aa 26 [2] 84 04 [2] 90 1f [2] 9f 05 [2] 81 18 [2] 83 19 [2] 98 1f [2] 84 18 [2] 98 37 }

  condition:
    any of them
}