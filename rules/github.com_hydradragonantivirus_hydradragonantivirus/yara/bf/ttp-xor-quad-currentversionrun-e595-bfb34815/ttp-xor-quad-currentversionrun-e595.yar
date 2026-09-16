rule TTP_XOR_QUAD_CurrentVersionRun_e595 {
  strings:
    $key_e595 = { b6 fa [2] 92 f4 [2] b9 d8 [2] 97 fa [2] 83 e1 [2] 8c fb [2] 92 e6 [2] 90 e7 [2] 8b e1 [2] 97 e6 [2] 8b c9 }

  condition:
    any of them
}