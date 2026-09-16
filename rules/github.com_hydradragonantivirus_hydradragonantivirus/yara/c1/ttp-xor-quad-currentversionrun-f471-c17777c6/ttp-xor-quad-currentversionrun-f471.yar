rule TTP_XOR_QUAD_CurrentVersionRun_f471 {
  strings:
    $key_f471 = { a7 1e [2] 83 10 [2] a8 3c [2] 86 1e [2] 92 05 [2] 9d 1f [2] 83 02 [2] 81 03 [2] 9a 05 [2] 86 02 [2] 9a 2d }

  condition:
    any of them
}