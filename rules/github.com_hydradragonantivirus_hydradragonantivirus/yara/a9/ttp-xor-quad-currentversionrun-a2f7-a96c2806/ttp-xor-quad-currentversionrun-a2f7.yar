rule TTP_XOR_QUAD_CurrentVersionRun_a2f7 {
  strings:
    $key_a2f7 = { f1 98 [2] d5 96 [2] fe ba [2] d0 98 [2] c4 83 [2] cb 99 [2] d5 84 [2] d7 85 [2] cc 83 [2] d0 84 [2] cc ab }

  condition:
    any of them
}