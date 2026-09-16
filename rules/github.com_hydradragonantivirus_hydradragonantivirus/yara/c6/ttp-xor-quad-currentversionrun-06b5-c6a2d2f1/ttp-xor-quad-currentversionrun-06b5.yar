rule TTP_XOR_QUAD_CurrentVersionRun_06b5 {
  strings:
    $key_06b5 = { 55 da [2] 71 d4 [2] 5a f8 [2] 74 da [2] 60 c1 [2] 6f db [2] 71 c6 [2] 73 c7 [2] 68 c1 [2] 74 c6 [2] 68 e9 }

  condition:
    any of them
}