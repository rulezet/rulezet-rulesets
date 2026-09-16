rule TTP_XOR_QUAD_CurrentVersionRun_a51d {
  strings:
    $key_a51d = { f6 72 [2] d2 7c [2] f9 50 [2] d7 72 [2] c3 69 [2] cc 73 [2] d2 6e [2] d0 6f [2] cb 69 [2] d7 6e [2] cb 41 }

  condition:
    any of them
}