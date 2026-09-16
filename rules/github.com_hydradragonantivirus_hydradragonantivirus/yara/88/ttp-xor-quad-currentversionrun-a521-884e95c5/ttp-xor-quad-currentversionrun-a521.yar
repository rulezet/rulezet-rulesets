rule TTP_XOR_QUAD_CurrentVersionRun_a521 {
  strings:
    $key_a521 = { f6 4e [2] d2 40 [2] f9 6c [2] d7 4e [2] c3 55 [2] cc 4f [2] d2 52 [2] d0 53 [2] cb 55 [2] d7 52 [2] cb 7d }

  condition:
    any of them
}