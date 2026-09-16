rule TTP_XOR_QUAD_CurrentVersionRun_bbd2 {
  strings:
    $key_bbd2 = { e8 bd [2] cc b3 [2] e7 9f [2] c9 bd [2] dd a6 [2] d2 bc [2] cc a1 [2] ce a0 [2] d5 a6 [2] c9 a1 [2] d5 8e }

  condition:
    any of them
}