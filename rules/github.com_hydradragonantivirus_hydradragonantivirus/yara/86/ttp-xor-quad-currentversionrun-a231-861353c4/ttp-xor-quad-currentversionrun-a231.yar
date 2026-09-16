rule TTP_XOR_QUAD_CurrentVersionRun_a231 {
  strings:
    $key_a231 = { f1 5e [2] d5 50 [2] fe 7c [2] d0 5e [2] c4 45 [2] cb 5f [2] d5 42 [2] d7 43 [2] cc 45 [2] d0 42 [2] cc 6d }

  condition:
    any of them
}