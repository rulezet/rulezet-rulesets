rule TTP_XOR_QUAD_CurrentVersionRun_6da8 {
  strings:
    $key_6da8 = { 3e c7 [2] 1a c9 [2] 31 e5 [2] 1f c7 [2] 0b dc [2] 04 c6 [2] 1a db [2] 18 da [2] 03 dc [2] 1f db [2] 03 f4 }

  condition:
    any of them
}