rule TTP_XOR_QUAD_CurrentVersionRun_b9d2 {
  strings:
    $key_b9d2 = { ea bd [2] ce b3 [2] e5 9f [2] cb bd [2] df a6 [2] d0 bc [2] ce a1 [2] cc a0 [2] d7 a6 [2] cb a1 [2] d7 8e }

  condition:
    any of them
}