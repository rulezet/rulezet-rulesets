rule TTP_XOR_QUAD_CurrentVersionRun_a28f {
  strings:
    $key_a28f = { f1 e0 [2] d5 ee [2] fe c2 [2] d0 e0 [2] c4 fb [2] cb e1 [2] d5 fc [2] d7 fd [2] cc fb [2] d0 fc [2] cc d3 }

  condition:
    any of them
}