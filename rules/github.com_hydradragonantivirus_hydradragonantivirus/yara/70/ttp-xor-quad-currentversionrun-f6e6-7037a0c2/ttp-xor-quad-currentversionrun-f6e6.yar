rule TTP_XOR_QUAD_CurrentVersionRun_f6e6 {
  strings:
    $key_f6e6 = { a5 89 [2] 81 87 [2] aa ab [2] 84 89 [2] 90 92 [2] 9f 88 [2] 81 95 [2] 83 94 [2] 98 92 [2] 84 95 [2] 98 ba }

  condition:
    any of them
}