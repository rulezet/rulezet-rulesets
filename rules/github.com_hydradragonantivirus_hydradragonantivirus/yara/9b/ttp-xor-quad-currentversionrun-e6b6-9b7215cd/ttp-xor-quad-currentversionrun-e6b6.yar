rule TTP_XOR_QUAD_CurrentVersionRun_e6b6 {
  strings:
    $key_e6b6 = { b5 d9 [2] 91 d7 [2] ba fb [2] 94 d9 [2] 80 c2 [2] 8f d8 [2] 91 c5 [2] 93 c4 [2] 88 c2 [2] 94 c5 [2] 88 ea }

  condition:
    any of them
}