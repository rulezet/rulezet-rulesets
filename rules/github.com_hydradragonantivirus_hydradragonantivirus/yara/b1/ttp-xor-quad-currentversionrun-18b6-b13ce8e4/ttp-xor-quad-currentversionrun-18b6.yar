rule TTP_XOR_QUAD_CurrentVersionRun_18b6 {
  strings:
    $key_18b6 = { 4b d9 [2] 6f d7 [2] 44 fb [2] 6a d9 [2] 7e c2 [2] 71 d8 [2] 6f c5 [2] 6d c4 [2] 76 c2 [2] 6a c5 [2] 76 ea }

  condition:
    any of them
}