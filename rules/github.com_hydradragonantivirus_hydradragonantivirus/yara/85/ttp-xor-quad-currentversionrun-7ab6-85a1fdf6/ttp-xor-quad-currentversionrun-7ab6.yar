rule TTP_XOR_QUAD_CurrentVersionRun_7ab6 {
  strings:
    $key_7ab6 = { 29 d9 [2] 0d d7 [2] 26 fb [2] 08 d9 [2] 1c c2 [2] 13 d8 [2] 0d c5 [2] 0f c4 [2] 14 c2 [2] 08 c5 [2] 14 ea }

  condition:
    any of them
}