rule TTP_XOR_QUAD_CurrentVersionRun_f6d1 {
  strings:
    $key_f6d1 = { a5 be [2] 81 b0 [2] aa 9c [2] 84 be [2] 90 a5 [2] 9f bf [2] 81 a2 [2] 83 a3 [2] 98 a5 [2] 84 a2 [2] 98 8d }

  condition:
    any of them
}