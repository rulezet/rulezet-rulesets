rule TTP_XOR_QUAD_CurrentVersionRun_2eb6 {
  strings:
    $key_2eb6 = { 7d d9 [2] 59 d7 [2] 72 fb [2] 5c d9 [2] 48 c2 [2] 47 d8 [2] 59 c5 [2] 5b c4 [2] 40 c2 [2] 5c c5 [2] 40 ea }

  condition:
    any of them
}