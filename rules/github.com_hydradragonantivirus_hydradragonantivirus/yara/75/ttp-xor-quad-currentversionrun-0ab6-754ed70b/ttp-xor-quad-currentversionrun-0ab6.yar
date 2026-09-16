rule TTP_XOR_QUAD_CurrentVersionRun_0ab6 {
  strings:
    $key_0ab6 = { 59 d9 [2] 7d d7 [2] 56 fb [2] 78 d9 [2] 6c c2 [2] 63 d8 [2] 7d c5 [2] 7f c4 [2] 64 c2 [2] 78 c5 [2] 64 ea }

  condition:
    any of them
}