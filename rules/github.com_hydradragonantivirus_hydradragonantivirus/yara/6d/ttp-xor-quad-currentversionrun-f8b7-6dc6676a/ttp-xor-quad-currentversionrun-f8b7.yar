rule TTP_XOR_QUAD_CurrentVersionRun_f8b7 {
  strings:
    $key_f8b7 = { ab d8 [2] 8f d6 [2] a4 fa [2] 8a d8 [2] 9e c3 [2] 91 d9 [2] 8f c4 [2] 8d c5 [2] 96 c3 [2] 8a c4 [2] 96 eb }

  condition:
    any of them
}