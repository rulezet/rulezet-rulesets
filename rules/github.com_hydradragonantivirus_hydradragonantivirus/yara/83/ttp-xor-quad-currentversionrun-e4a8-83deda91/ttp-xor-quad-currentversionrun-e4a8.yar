rule TTP_XOR_QUAD_CurrentVersionRun_e4a8 {
  strings:
    $key_e4a8 = { b7 c7 [2] 93 c9 [2] b8 e5 [2] 96 c7 [2] 82 dc [2] 8d c6 [2] 93 db [2] 91 da [2] 8a dc [2] 96 db [2] 8a f4 }

  condition:
    any of them
}