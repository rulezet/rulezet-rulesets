rule TTP_XOR_QUAD_CurrentVersionRun_f673 {
  strings:
    $key_f673 = { a5 1c [2] 81 12 [2] aa 3e [2] 84 1c [2] 90 07 [2] 9f 1d [2] 81 00 [2] 83 01 [2] 98 07 [2] 84 00 [2] 98 2f }

  condition:
    any of them
}