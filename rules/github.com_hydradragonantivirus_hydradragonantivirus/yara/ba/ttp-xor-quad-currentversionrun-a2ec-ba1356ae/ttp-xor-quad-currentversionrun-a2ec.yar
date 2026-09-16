rule TTP_XOR_QUAD_CurrentVersionRun_a2ec {
  strings:
    $key_a2ec = { f1 83 [2] d5 8d [2] fe a1 [2] d0 83 [2] c4 98 [2] cb 82 [2] d5 9f [2] d7 9e [2] cc 98 [2] d0 9f [2] cc b0 }

  condition:
    any of them
}