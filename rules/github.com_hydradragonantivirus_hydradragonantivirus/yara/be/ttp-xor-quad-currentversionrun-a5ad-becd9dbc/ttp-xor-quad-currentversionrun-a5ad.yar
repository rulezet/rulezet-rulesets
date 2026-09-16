rule TTP_XOR_QUAD_CurrentVersionRun_a5ad {
  strings:
    $key_a5ad = { f6 c2 [2] d2 cc [2] f9 e0 [2] d7 c2 [2] c3 d9 [2] cc c3 [2] d2 de [2] d0 df [2] cb d9 [2] d7 de [2] cb f1 }

  condition:
    any of them
}