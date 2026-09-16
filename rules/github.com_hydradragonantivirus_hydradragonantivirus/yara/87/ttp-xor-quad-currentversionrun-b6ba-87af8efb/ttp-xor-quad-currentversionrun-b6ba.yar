rule TTP_XOR_QUAD_CurrentVersionRun_b6ba {
  strings:
    $key_b6ba = { e5 d5 [2] c1 db [2] ea f7 [2] c4 d5 [2] d0 ce [2] df d4 [2] c1 c9 [2] c3 c8 [2] d8 ce [2] c4 c9 [2] d8 e6 }

  condition:
    any of them
}