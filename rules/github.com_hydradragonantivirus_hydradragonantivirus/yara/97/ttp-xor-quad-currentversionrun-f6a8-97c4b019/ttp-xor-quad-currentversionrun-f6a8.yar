rule TTP_XOR_QUAD_CurrentVersionRun_f6a8 {
  strings:
    $key_f6a8 = { a5 c7 [2] 81 c9 [2] aa e5 [2] 84 c7 [2] 90 dc [2] 9f c6 [2] 81 db [2] 83 da [2] 98 dc [2] 84 db [2] 98 f4 }

  condition:
    any of them
}