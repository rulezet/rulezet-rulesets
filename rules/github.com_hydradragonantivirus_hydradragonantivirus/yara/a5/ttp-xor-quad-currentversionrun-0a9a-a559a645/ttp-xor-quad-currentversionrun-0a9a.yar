rule TTP_XOR_QUAD_CurrentVersionRun_0a9a {
  strings:
    $key_0a9a = { 59 f5 [2] 7d fb [2] 56 d7 [2] 78 f5 [2] 6c ee [2] 63 f4 [2] 7d e9 [2] 7f e8 [2] 64 ee [2] 78 e9 [2] 64 c6 }

  condition:
    any of them
}