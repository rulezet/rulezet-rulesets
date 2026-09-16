rule TTP_XOR_QUAD_CurrentVersionRun_e4b6 {
  strings:
    $key_e4b6 = { b7 d9 [2] 93 d7 [2] b8 fb [2] 96 d9 [2] 82 c2 [2] 8d d8 [2] 93 c5 [2] 91 c4 [2] 8a c2 [2] 96 c5 [2] 8a ea }

  condition:
    any of them
}