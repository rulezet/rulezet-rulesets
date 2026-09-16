rule TTP_XOR_QUAD_CurrentVersionRun_62b6 {
  strings:
    $key_62b6 = { 31 d9 [2] 15 d7 [2] 3e fb [2] 10 d9 [2] 04 c2 [2] 0b d8 [2] 15 c5 [2] 17 c4 [2] 0c c2 [2] 10 c5 [2] 0c ea }

  condition:
    any of them
}