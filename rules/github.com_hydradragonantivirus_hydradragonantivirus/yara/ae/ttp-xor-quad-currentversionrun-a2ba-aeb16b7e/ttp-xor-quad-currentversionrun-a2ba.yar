rule TTP_XOR_QUAD_CurrentVersionRun_a2ba {
  strings:
    $key_a2ba = { f1 d5 [2] d5 db [2] fe f7 [2] d0 d5 [2] c4 ce [2] cb d4 [2] d5 c9 [2] d7 c8 [2] cc ce [2] d0 c9 [2] cc e6 }

  condition:
    any of them
}