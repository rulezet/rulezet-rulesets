rule TTP_XOR_QUAD_CurrentVersionRun_a51f {
  strings:
    $key_a51f = { f6 70 [2] d2 7e [2] f9 52 [2] d7 70 [2] c3 6b [2] cc 71 [2] d2 6c [2] d0 6d [2] cb 6b [2] d7 6c [2] cb 43 }

  condition:
    any of them
}