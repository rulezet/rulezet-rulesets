rule TTP_XOR_QUAD_CurrentVersionRun_a5c0 {
  strings:
    $key_a5c0 = { f6 af [2] d2 a1 [2] f9 8d [2] d7 af [2] c3 b4 [2] cc ae [2] d2 b3 [2] d0 b2 [2] cb b4 [2] d7 b3 [2] cb 9c }

  condition:
    any of them
}