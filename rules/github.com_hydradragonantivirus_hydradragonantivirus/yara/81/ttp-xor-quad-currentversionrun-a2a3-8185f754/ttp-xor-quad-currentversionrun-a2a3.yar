rule TTP_XOR_QUAD_CurrentVersionRun_a2a3 {
  strings:
    $key_a2a3 = { f1 cc [2] d5 c2 [2] fe ee [2] d0 cc [2] c4 d7 [2] cb cd [2] d5 d0 [2] d7 d1 [2] cc d7 [2] d0 d0 [2] cc ff }

  condition:
    any of them
}