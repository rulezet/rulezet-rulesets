rule TTP_XOR_QUAD_CurrentVersionRun_62b4 {
  strings:
    $key_62b4 = { 31 db [2] 15 d5 [2] 3e f9 [2] 10 db [2] 04 c0 [2] 0b da [2] 15 c7 [2] 17 c6 [2] 0c c0 [2] 10 c7 [2] 0c e8 }

  condition:
    any of them
}