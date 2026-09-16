rule TTP_XOR_QUAD_CurrentVersionRun_e3b6 {
  strings:
    $key_e3b6 = { b0 d9 [2] 94 d7 [2] bf fb [2] 91 d9 [2] 85 c2 [2] 8a d8 [2] 94 c5 [2] 96 c4 [2] 8d c2 [2] 91 c5 [2] 8d ea }

  condition:
    any of them
}