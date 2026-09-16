rule TTP_XOR_QUAD_CurrentVersionRun_a50a {
  strings:
    $key_a50a = { f6 65 [2] d2 6b [2] f9 47 [2] d7 65 [2] c3 7e [2] cc 64 [2] d2 79 [2] d0 78 [2] cb 7e [2] d7 79 [2] cb 56 }

  condition:
    any of them
}