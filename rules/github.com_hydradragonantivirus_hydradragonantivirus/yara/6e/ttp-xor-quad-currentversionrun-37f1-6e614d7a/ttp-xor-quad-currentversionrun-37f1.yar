rule TTP_XOR_QUAD_CurrentVersionRun_37f1 {
  strings:
    $key_37f1 = { 64 9e [2] 40 90 [2] 6b bc [2] 45 9e [2] 51 85 [2] 5e 9f [2] 40 82 [2] 42 83 [2] 59 85 [2] 45 82 [2] 59 ad }

  condition:
    any of them
}