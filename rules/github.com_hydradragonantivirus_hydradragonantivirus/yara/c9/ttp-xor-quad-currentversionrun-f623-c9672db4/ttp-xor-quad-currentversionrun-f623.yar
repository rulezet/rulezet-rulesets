rule TTP_XOR_QUAD_CurrentVersionRun_f623 {
  strings:
    $key_f623 = { a5 4c [2] 81 42 [2] aa 6e [2] 84 4c [2] 90 57 [2] 9f 4d [2] 81 50 [2] 83 51 [2] 98 57 [2] 84 50 [2] 98 7f }

  condition:
    any of them
}