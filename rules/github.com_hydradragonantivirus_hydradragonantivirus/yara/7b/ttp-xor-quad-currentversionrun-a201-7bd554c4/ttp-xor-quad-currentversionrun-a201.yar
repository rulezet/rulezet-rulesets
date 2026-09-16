rule TTP_XOR_QUAD_CurrentVersionRun_a201 {
  strings:
    $key_a201 = { f1 6e [2] d5 60 [2] fe 4c [2] d0 6e [2] c4 75 [2] cb 6f [2] d5 72 [2] d7 73 [2] cc 75 [2] d0 72 [2] cc 5d }

  condition:
    any of them
}