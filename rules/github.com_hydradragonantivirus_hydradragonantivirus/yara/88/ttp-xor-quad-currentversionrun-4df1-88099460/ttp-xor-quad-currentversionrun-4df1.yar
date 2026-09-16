rule TTP_XOR_QUAD_CurrentVersionRun_4df1 {
  strings:
    $key_4df1 = { 1e 9e [2] 3a 90 [2] 11 bc [2] 3f 9e [2] 2b 85 [2] 24 9f [2] 3a 82 [2] 38 83 [2] 23 85 [2] 3f 82 [2] 23 ad }

  condition:
    any of them
}