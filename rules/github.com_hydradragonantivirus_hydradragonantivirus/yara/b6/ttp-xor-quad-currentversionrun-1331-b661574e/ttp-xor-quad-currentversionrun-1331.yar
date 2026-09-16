rule TTP_XOR_QUAD_CurrentVersionRun_1331 {
  strings:
    $key_1331 = { 40 5e [2] 64 50 [2] 4f 7c [2] 61 5e [2] 75 45 [2] 7a 5f [2] 64 42 [2] 66 43 [2] 7d 45 [2] 61 42 [2] 7d 6d }

  condition:
    any of them
}