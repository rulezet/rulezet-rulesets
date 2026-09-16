rule TTP_XOR_QUAD_CurrentVersionRun_b9c0 {
  strings:
    $key_b9c0 = { ea af [2] ce a1 [2] e5 8d [2] cb af [2] df b4 [2] d0 ae [2] ce b3 [2] cc b2 [2] d7 b4 [2] cb b3 [2] d7 9c }

  condition:
    any of them
}