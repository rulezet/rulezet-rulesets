rule TTP_XOR_QUAD_CurrentVersionRun_b9c4 {
  strings:
    $key_b9c4 = { ea ab [2] ce a5 [2] e5 89 [2] cb ab [2] df b0 [2] d0 aa [2] ce b7 [2] cc b6 [2] d7 b0 [2] cb b7 [2] d7 98 }

  condition:
    any of them
}