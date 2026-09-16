rule TTP_XOR_QUAD_CurrentVersionRun_e6b5 {
  strings:
    $key_e6b5 = { b5 da [2] 91 d4 [2] ba f8 [2] 94 da [2] 80 c1 [2] 8f db [2] 91 c6 [2] 93 c7 [2] 88 c1 [2] 94 c6 [2] 88 e9 }

  condition:
    any of them
}