rule TTP_XOR_QUAD_CurrentVersionRun_d39a {
  strings:
    $key_d39a = { 80 f5 [2] a4 fb [2] 8f d7 [2] a1 f5 [2] b5 ee [2] ba f4 [2] a4 e9 [2] a6 e8 [2] bd ee [2] a1 e9 [2] bd c6 }

  condition:
    any of them
}