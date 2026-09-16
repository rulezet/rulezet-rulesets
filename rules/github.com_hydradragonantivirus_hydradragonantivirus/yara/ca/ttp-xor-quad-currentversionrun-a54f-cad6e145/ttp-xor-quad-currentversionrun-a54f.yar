rule TTP_XOR_QUAD_CurrentVersionRun_a54f {
  strings:
    $key_a54f = { f6 20 [2] d2 2e [2] f9 02 [2] d7 20 [2] c3 3b [2] cc 21 [2] d2 3c [2] d0 3d [2] cb 3b [2] d7 3c [2] cb 13 }

  condition:
    any of them
}