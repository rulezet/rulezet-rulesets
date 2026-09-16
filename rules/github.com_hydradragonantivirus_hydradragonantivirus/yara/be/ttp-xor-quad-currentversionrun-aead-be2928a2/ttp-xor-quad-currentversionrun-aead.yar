rule TTP_XOR_QUAD_CurrentVersionRun_aead {
  strings:
    $key_aead = { fd c2 [2] d9 cc [2] f2 e0 [2] dc c2 [2] c8 d9 [2] c7 c3 [2] d9 de [2] db df [2] c0 d9 [2] dc de [2] c0 f1 }

  condition:
    any of them
}