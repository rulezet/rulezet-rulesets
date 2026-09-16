rule TTP_XOR_QUAD_CurrentVersionRun_f6b6 {
  strings:
    $key_f6b6 = { a5 d9 [2] 81 d7 [2] aa fb [2] 84 d9 [2] 90 c2 [2] 9f d8 [2] 81 c5 [2] 83 c4 [2] 98 c2 [2] 84 c5 [2] 98 ea }

  condition:
    any of them
}