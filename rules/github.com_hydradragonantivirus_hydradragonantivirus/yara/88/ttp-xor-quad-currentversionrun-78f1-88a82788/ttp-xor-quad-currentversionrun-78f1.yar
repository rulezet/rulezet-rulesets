rule TTP_XOR_QUAD_CurrentVersionRun_78f1 {
  strings:
    $key_78f1 = { 2b 9e [2] 0f 90 [2] 24 bc [2] 0a 9e [2] 1e 85 [2] 11 9f [2] 0f 82 [2] 0d 83 [2] 16 85 [2] 0a 82 [2] 16 ad }

  condition:
    any of them
}