rule TTP_XOR_QUAD_CurrentVersionRun_a513 {
  strings:
    $key_a513 = { f6 7c [2] d2 72 [2] f9 5e [2] d7 7c [2] c3 67 [2] cc 7d [2] d2 60 [2] d0 61 [2] cb 67 [2] d7 60 [2] cb 4f }

  condition:
    any of them
}