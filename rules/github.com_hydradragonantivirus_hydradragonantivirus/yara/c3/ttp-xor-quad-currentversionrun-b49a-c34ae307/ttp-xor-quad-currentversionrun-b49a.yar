rule TTP_XOR_QUAD_CurrentVersionRun_b49a {
  strings:
    $key_b49a = { e7 f5 [2] c3 fb [2] e8 d7 [2] c6 f5 [2] d2 ee [2] dd f4 [2] c3 e9 [2] c1 e8 [2] da ee [2] c6 e9 [2] da c6 }

  condition:
    any of them
}