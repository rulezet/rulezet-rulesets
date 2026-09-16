rule TTP_XOR_QUAD_CurrentVersionRun_a55f {
  strings:
    $key_a55f = { f6 30 [2] d2 3e [2] f9 12 [2] d7 30 [2] c3 2b [2] cc 31 [2] d2 2c [2] d0 2d [2] cb 2b [2] d7 2c [2] cb 03 }

  condition:
    any of them
}