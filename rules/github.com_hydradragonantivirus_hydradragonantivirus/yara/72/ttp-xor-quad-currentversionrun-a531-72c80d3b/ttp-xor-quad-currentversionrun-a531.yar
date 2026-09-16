rule TTP_XOR_QUAD_CurrentVersionRun_a531 {
  strings:
    $key_a531 = { f6 5e [2] d2 50 [2] f9 7c [2] d7 5e [2] c3 45 [2] cc 5f [2] d2 42 [2] d0 43 [2] cb 45 [2] d7 42 [2] cb 6d }

  condition:
    any of them
}