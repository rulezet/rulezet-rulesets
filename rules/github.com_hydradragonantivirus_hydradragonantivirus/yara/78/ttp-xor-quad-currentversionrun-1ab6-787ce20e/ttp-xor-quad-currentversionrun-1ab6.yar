rule TTP_XOR_QUAD_CurrentVersionRun_1ab6 {
  strings:
    $key_1ab6 = { 49 d9 [2] 6d d7 [2] 46 fb [2] 68 d9 [2] 7c c2 [2] 73 d8 [2] 6d c5 [2] 6f c4 [2] 74 c2 [2] 68 c5 [2] 74 ea }

  condition:
    any of them
}