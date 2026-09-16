rule TTP_XOR_QUAD_CurrentVersionRun_a5f7 {
  strings:
    $key_a5f7 = { f6 98 [2] d2 96 [2] f9 ba [2] d7 98 [2] c3 83 [2] cc 99 [2] d2 84 [2] d0 85 [2] cb 83 [2] d7 84 [2] cb ab }

  condition:
    any of them
}