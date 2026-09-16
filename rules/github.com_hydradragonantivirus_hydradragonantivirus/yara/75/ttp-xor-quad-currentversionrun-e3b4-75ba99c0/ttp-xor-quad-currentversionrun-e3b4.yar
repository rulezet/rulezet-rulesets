rule TTP_XOR_QUAD_CurrentVersionRun_e3b4 {
  strings:
    $key_e3b4 = { b0 db [2] 94 d5 [2] bf f9 [2] 91 db [2] 85 c0 [2] 8a da [2] 94 c7 [2] 96 c6 [2] 8d c0 [2] 91 c7 [2] 8d e8 }

  condition:
    any of them
}