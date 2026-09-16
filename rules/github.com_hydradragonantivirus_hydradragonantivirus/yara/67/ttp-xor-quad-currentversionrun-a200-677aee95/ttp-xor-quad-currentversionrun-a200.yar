rule TTP_XOR_QUAD_CurrentVersionRun_a200 {
  strings:
    $key_a200 = { f1 6f [2] d5 61 [2] fe 4d [2] d0 6f [2] c4 74 [2] cb 6e [2] d5 73 [2] d7 72 [2] cc 74 [2] d0 73 [2] cc 5c }

  condition:
    any of them
}