rule TTP_XOR_QUAD_CurrentVersionRun_05b6 {
  strings:
    $key_05b6 = { 56 d9 [2] 72 d7 [2] 59 fb [2] 77 d9 [2] 63 c2 [2] 6c d8 [2] 72 c5 [2] 70 c4 [2] 6b c2 [2] 77 c5 [2] 6b ea }

  condition:
    any of them
}