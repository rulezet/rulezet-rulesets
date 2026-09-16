rule TTP_XOR_QUAD_CurrentVersionRun_15b6 {
  strings:
    $key_15b6 = { 46 d9 [2] 62 d7 [2] 49 fb [2] 67 d9 [2] 73 c2 [2] 7c d8 [2] 62 c5 [2] 60 c4 [2] 7b c2 [2] 67 c5 [2] 7b ea }

  condition:
    any of them
}