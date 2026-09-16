rule TTP_XOR_QUAD_CurrentVersionRun_5da8 {
  strings:
    $key_5da8 = { 0e c7 [2] 2a c9 [2] 01 e5 [2] 2f c7 [2] 3b dc [2] 34 c6 [2] 2a db [2] 28 da [2] 33 dc [2] 2f db [2] 33 f4 }

  condition:
    any of them
}