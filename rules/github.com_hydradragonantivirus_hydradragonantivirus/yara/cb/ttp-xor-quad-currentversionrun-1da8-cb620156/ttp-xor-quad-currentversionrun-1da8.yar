rule TTP_XOR_QUAD_CurrentVersionRun_1da8 {
  strings:
    $key_1da8 = { 4e c7 [2] 6a c9 [2] 41 e5 [2] 6f c7 [2] 7b dc [2] 74 c6 [2] 6a db [2] 68 da [2] 73 dc [2] 6f db [2] 73 f4 }

  condition:
    any of them
}