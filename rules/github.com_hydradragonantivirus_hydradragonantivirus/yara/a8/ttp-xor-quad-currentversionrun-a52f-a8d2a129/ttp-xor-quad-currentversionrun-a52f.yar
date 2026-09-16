rule TTP_XOR_QUAD_CurrentVersionRun_a52f {
  strings:
    $key_a52f = { f6 40 [2] d2 4e [2] f9 62 [2] d7 40 [2] c3 5b [2] cc 41 [2] d2 5c [2] d0 5d [2] cb 5b [2] d7 5c [2] cb 73 }

  condition:
    any of them
}