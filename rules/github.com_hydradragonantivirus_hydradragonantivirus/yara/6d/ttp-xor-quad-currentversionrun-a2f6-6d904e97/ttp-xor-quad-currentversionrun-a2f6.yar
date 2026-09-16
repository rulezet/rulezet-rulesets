rule TTP_XOR_QUAD_CurrentVersionRun_a2f6 {
  strings:
    $key_a2f6 = { f1 99 [2] d5 97 [2] fe bb [2] d0 99 [2] c4 82 [2] cb 98 [2] d5 85 [2] d7 84 [2] cc 82 [2] d0 85 [2] cc aa }

  condition:
    any of them
}