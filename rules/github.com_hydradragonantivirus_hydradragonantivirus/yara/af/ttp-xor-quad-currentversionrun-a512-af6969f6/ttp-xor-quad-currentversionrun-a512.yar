rule TTP_XOR_QUAD_CurrentVersionRun_a512 {
  strings:
    $key_a512 = { f6 7d [2] d2 73 [2] f9 5f [2] d7 7d [2] c3 66 [2] cc 7c [2] d2 61 [2] d0 60 [2] cb 66 [2] d7 61 [2] cb 4e }

  condition:
    any of them
}