rule TTP_XOR_QUAD_CurrentVersionRun_acaf {
  strings:
    $key_acaf = { ff c0 [2] db ce [2] f0 e2 [2] de c0 [2] ca db [2] c5 c1 [2] db dc [2] d9 dd [2] c2 db [2] de dc [2] c2 f3 }

  condition:
    any of them
}