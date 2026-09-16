rule TTP_XOR_QUAD_CurrentVersionRun_a501 {
  strings:
    $key_a501 = { f6 6e [2] d2 60 [2] f9 4c [2] d7 6e [2] c3 75 [2] cc 6f [2] d2 72 [2] d0 73 [2] cb 75 [2] d7 72 [2] cb 5d }

  condition:
    any of them
}