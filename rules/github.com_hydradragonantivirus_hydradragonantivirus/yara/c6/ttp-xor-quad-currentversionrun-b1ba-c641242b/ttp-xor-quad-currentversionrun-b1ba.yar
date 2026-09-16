rule TTP_XOR_QUAD_CurrentVersionRun_b1ba {
  strings:
    $key_b1ba = { e2 d5 [2] c6 db [2] ed f7 [2] c3 d5 [2] d7 ce [2] d8 d4 [2] c6 c9 [2] c4 c8 [2] df ce [2] c3 c9 [2] df e6 }

  condition:
    any of them
}