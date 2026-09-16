rule TTP_XOR_QUAD_CurrentVersionRun_54b6 {
  strings:
    $key_54b6 = { 07 d9 [2] 23 d7 [2] 08 fb [2] 26 d9 [2] 32 c2 [2] 3d d8 [2] 23 c5 [2] 21 c4 [2] 3a c2 [2] 26 c5 [2] 3a ea }

  condition:
    any of them
}