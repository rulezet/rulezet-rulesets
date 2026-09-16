rule TTP_XOR_QUAD_CurrentVersionRun_d79a {
  strings:
    $key_d79a = { 84 f5 [2] a0 fb [2] 8b d7 [2] a5 f5 [2] b1 ee [2] be f4 [2] a0 e9 [2] a2 e8 [2] b9 ee [2] a5 e9 [2] b9 c6 }

  condition:
    any of them
}