rule TTP_XOR_QUAD_CurrentVersionRun_a5c5 {
  strings:
    $key_a5c5 = { f6 aa [2] d2 a4 [2] f9 88 [2] d7 aa [2] c3 b1 [2] cc ab [2] d2 b6 [2] d0 b7 [2] cb b1 [2] d7 b6 [2] cb 99 }

  condition:
    any of them
}