rule TTP_XOR_QUAD_CurrentVersionRun_f663 {
  strings:
    $key_f663 = { a5 0c [2] 81 02 [2] aa 2e [2] 84 0c [2] 90 17 [2] 9f 0d [2] 81 10 [2] 83 11 [2] 98 17 [2] 84 10 [2] 98 3f }

  condition:
    any of them
}