rule TTP_XOR_QUAD_CurrentVersionRun_a578 {
  strings:
    $key_a578 = { f6 17 [2] d2 19 [2] f9 35 [2] d7 17 [2] c3 0c [2] cc 16 [2] d2 0b [2] d0 0a [2] cb 0c [2] d7 0b [2] cb 24 }

  condition:
    any of them
}