rule TTP_XOR_QUAD_CurrentVersionRun_a5fa {
  strings:
    $key_a5fa = { f6 95 [2] d2 9b [2] f9 b7 [2] d7 95 [2] c3 8e [2] cc 94 [2] d2 89 [2] d0 88 [2] cb 8e [2] d7 89 [2] cb a6 }

  condition:
    any of them
}