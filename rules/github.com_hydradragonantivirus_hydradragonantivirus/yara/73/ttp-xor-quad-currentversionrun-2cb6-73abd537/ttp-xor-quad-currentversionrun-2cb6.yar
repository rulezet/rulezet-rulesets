rule TTP_XOR_QUAD_CurrentVersionRun_2cb6 {
  strings:
    $key_2cb6 = { 7f d9 [2] 5b d7 [2] 70 fb [2] 5e d9 [2] 4a c2 [2] 45 d8 [2] 5b c5 [2] 59 c4 [2] 42 c2 [2] 5e c5 [2] 42 ea }

  condition:
    any of them
}