rule TTP_XOR_QUAD_CurrentVersionRun_a5e2 {
  strings:
    $key_a5e2 = { f6 8d [2] d2 83 [2] f9 af [2] d7 8d [2] c3 96 [2] cc 8c [2] d2 91 [2] d0 90 [2] cb 96 [2] d7 91 [2] cb be }

  condition:
    any of them
}