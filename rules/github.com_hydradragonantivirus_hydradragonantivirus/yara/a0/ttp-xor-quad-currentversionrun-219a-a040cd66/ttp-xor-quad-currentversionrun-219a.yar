rule TTP_XOR_QUAD_CurrentVersionRun_219a {
  strings:
    $key_219a = { 72 f5 [2] 56 fb [2] 7d d7 [2] 53 f5 [2] 47 ee [2] 48 f4 [2] 56 e9 [2] 54 e8 [2] 4f ee [2] 53 e9 [2] 4f c6 }

  condition:
    any of them
}