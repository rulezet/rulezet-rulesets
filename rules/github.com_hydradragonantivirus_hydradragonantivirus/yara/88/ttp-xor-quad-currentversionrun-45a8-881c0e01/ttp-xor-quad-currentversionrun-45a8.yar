rule TTP_XOR_QUAD_CurrentVersionRun_45a8 {
  strings:
    $key_45a8 = { 16 c7 [2] 32 c9 [2] 19 e5 [2] 37 c7 [2] 23 dc [2] 2c c6 [2] 32 db [2] 30 da [2] 2b dc [2] 37 db [2] 2b f4 }

  condition:
    any of them
}