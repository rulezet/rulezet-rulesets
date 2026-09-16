rule TTP_XOR_QUAD_CurrentVersionRun_119a {
  strings:
    $key_119a = { 42 f5 [2] 66 fb [2] 4d d7 [2] 63 f5 [2] 77 ee [2] 78 f4 [2] 66 e9 [2] 64 e8 [2] 7f ee [2] 63 e9 [2] 7f c6 }

  condition:
    any of them
}