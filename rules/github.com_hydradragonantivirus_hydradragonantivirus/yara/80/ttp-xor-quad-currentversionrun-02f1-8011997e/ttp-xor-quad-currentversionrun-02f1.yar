rule TTP_XOR_QUAD_CurrentVersionRun_02f1 {
  strings:
    $key_02f1 = { 51 9e [2] 75 90 [2] 5e bc [2] 70 9e [2] 64 85 [2] 6b 9f [2] 75 82 [2] 77 83 [2] 6c 85 [2] 70 82 [2] 6c ad }

  condition:
    any of them
}