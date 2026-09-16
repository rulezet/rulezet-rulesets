rule TTP_XOR_QUAD_CurrentVersionRun_b9c9 {
  strings:
    $key_b9c9 = { ea a6 [2] ce a8 [2] e5 84 [2] cb a6 [2] df bd [2] d0 a7 [2] ce ba [2] cc bb [2] d7 bd [2] cb ba [2] d7 95 }

  condition:
    any of them
}