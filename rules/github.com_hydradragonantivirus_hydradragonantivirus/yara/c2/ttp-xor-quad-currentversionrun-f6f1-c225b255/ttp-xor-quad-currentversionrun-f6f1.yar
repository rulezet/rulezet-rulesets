rule TTP_XOR_QUAD_CurrentVersionRun_f6f1 {
  strings:
    $key_f6f1 = { a5 9e [2] 81 90 [2] aa bc [2] 84 9e [2] 90 85 [2] 9f 9f [2] 81 82 [2] 83 83 [2] 98 85 [2] 84 82 [2] 98 ad }

  condition:
    any of them
}