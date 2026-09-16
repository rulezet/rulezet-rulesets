rule TTP_XOR_QUAD_CurrentVersionRun_52b6 {
  strings:
    $key_52b6 = { 01 d9 [2] 25 d7 [2] 0e fb [2] 20 d9 [2] 34 c2 [2] 3b d8 [2] 25 c5 [2] 27 c4 [2] 3c c2 [2] 20 c5 [2] 3c ea }

  condition:
    any of them
}