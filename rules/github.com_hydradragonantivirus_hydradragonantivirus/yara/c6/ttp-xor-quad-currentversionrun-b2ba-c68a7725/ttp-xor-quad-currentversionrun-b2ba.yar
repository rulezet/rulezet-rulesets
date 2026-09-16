rule TTP_XOR_QUAD_CurrentVersionRun_b2ba {
  strings:
    $key_b2ba = { e1 d5 [2] c5 db [2] ee f7 [2] c0 d5 [2] d4 ce [2] db d4 [2] c5 c9 [2] c7 c8 [2] dc ce [2] c0 c9 [2] dc e6 }

  condition:
    any of them
}