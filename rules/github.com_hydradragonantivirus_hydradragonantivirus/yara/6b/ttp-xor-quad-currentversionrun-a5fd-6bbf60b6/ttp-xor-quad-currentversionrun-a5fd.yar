rule TTP_XOR_QUAD_CurrentVersionRun_a5fd {
  strings:
    $key_a5fd = { f6 92 [2] d2 9c [2] f9 b0 [2] d7 92 [2] c3 89 [2] cc 93 [2] d2 8e [2] d0 8f [2] cb 89 [2] d7 8e [2] cb a1 }

  condition:
    any of them
}