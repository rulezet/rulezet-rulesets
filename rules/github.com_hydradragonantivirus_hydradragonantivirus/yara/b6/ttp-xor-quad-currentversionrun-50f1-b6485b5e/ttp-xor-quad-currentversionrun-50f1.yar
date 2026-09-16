rule TTP_XOR_QUAD_CurrentVersionRun_50f1 {
  strings:
    $key_50f1 = { 03 9e [2] 27 90 [2] 0c bc [2] 22 9e [2] 36 85 [2] 39 9f [2] 27 82 [2] 25 83 [2] 3e 85 [2] 22 82 [2] 3e ad }

  condition:
    any of them
}