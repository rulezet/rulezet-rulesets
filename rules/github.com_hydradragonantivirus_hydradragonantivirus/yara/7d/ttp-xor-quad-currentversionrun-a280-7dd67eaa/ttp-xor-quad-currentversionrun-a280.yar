rule TTP_XOR_QUAD_CurrentVersionRun_a280 {
  strings:
    $key_a280 = { f1 ef [2] d5 e1 [2] fe cd [2] d0 ef [2] c4 f4 [2] cb ee [2] d5 f3 [2] d7 f2 [2] cc f4 [2] d0 f3 [2] cc dc }

  condition:
    any of them
}