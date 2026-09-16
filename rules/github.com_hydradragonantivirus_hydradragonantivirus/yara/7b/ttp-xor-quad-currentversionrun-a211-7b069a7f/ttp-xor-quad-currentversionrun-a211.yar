rule TTP_XOR_QUAD_CurrentVersionRun_a211 {
  strings:
    $key_a211 = { f1 7e [2] d5 70 [2] fe 5c [2] d0 7e [2] c4 65 [2] cb 7f [2] d5 62 [2] d7 63 [2] cc 65 [2] d0 62 [2] cc 4d }

  condition:
    any of them
}