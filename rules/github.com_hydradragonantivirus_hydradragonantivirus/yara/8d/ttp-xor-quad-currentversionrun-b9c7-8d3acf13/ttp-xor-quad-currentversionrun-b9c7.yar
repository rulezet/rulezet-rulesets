rule TTP_XOR_QUAD_CurrentVersionRun_b9c7 {
  strings:
    $key_b9c7 = { ea a8 [2] ce a6 [2] e5 8a [2] cb a8 [2] df b3 [2] d0 a9 [2] ce b4 [2] cc b5 [2] d7 b3 [2] cb b4 [2] d7 9b }

  condition:
    any of them
}