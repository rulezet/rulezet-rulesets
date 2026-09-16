rule TTP_XOR_QUAD_CurrentVersionRun_a2bf {
  strings:
    $key_a2bf = { f1 d0 [2] d5 de [2] fe f2 [2] d0 d0 [2] c4 cb [2] cb d1 [2] d5 cc [2] d7 cd [2] cc cb [2] d0 cc [2] cc e3 }

  condition:
    any of them
}