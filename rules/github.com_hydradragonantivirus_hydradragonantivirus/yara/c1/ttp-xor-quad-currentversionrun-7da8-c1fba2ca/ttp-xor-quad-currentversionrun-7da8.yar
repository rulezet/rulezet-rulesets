rule TTP_XOR_QUAD_CurrentVersionRun_7da8 {
  strings:
    $key_7da8 = { 2e c7 [2] 0a c9 [2] 21 e5 [2] 0f c7 [2] 1b dc [2] 14 c6 [2] 0a db [2] 08 da [2] 13 dc [2] 0f db [2] 13 f4 }

  condition:
    any of them
}