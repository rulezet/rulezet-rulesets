rule TTP_XOR_QUAD_CurrentVersionRun_20f1 {
  strings:
    $key_20f1 = { 73 9e [2] 57 90 [2] 7c bc [2] 52 9e [2] 46 85 [2] 49 9f [2] 57 82 [2] 55 83 [2] 4e 85 [2] 52 82 [2] 4e ad }

  condition:
    any of them
}