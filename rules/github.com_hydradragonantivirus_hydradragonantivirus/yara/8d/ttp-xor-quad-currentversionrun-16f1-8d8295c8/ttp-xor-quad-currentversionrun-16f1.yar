rule TTP_XOR_QUAD_CurrentVersionRun_16f1 {
  strings:
    $key_16f1 = { 45 9e [2] 61 90 [2] 4a bc [2] 64 9e [2] 70 85 [2] 7f 9f [2] 61 82 [2] 63 83 [2] 78 85 [2] 64 82 [2] 78 ad }

  condition:
    any of them
}