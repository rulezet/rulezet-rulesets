rule TTP_XOR_QUAD_CurrentVersionRun_e591 {
  strings:
    $key_e591 = { b6 fe [2] 92 f0 [2] b9 dc [2] 97 fe [2] 83 e5 [2] 8c ff [2] 92 e2 [2] 90 e3 [2] 8b e5 [2] 97 e2 [2] 8b cd }

  condition:
    any of them
}