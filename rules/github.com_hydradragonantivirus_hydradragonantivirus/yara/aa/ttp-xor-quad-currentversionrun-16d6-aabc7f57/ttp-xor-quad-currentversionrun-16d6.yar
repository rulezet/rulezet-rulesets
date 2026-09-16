rule TTP_XOR_QUAD_CurrentVersionRun_16d6 {
  strings:
    $key_16d6 = { 45 b9 [2] 61 b7 [2] 4a 9b [2] 64 b9 [2] 70 a2 [2] 7f b8 [2] 61 a5 [2] 63 a4 [2] 78 a2 [2] 64 a5 [2] 78 8a }

  condition:
    any of them
}