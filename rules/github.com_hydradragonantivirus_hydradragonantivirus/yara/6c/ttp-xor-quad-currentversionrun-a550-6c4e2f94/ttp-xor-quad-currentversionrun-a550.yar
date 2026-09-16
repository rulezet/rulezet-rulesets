rule TTP_XOR_QUAD_CurrentVersionRun_a550 {
  strings:
    $key_a550 = { f6 3f [2] d2 31 [2] f9 1d [2] d7 3f [2] c3 24 [2] cc 3e [2] d2 23 [2] d0 22 [2] cb 24 [2] d7 23 [2] cb 0c }

  condition:
    any of them
}