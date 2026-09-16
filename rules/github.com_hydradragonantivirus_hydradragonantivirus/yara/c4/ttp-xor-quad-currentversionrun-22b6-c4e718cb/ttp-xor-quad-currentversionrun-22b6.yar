rule TTP_XOR_QUAD_CurrentVersionRun_22b6 {
  strings:
    $key_22b6 = { 71 d9 [2] 55 d7 [2] 7e fb [2] 50 d9 [2] 44 c2 [2] 4b d8 [2] 55 c5 [2] 57 c4 [2] 4c c2 [2] 50 c5 [2] 4c ea }

  condition:
    any of them
}