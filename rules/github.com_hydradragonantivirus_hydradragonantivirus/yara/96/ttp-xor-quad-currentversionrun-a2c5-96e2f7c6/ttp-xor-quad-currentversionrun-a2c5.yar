rule TTP_XOR_QUAD_CurrentVersionRun_a2c5 {
  strings:
    $key_a2c5 = { f1 aa [2] d5 a4 [2] fe 88 [2] d0 aa [2] c4 b1 [2] cb ab [2] d5 b6 [2] d7 b7 [2] cc b1 [2] d0 b6 [2] cc 99 }

  condition:
    any of them
}