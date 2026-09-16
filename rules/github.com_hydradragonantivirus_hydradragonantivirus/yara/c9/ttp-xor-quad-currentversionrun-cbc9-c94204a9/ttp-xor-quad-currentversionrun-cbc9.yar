rule TTP_XOR_QUAD_CurrentVersionRun_cbc9 {
  strings:
    $key_cbc9 = { 98 a6 [2] bc a8 [2] 97 84 [2] b9 a6 [2] ad bd [2] a2 a7 [2] bc ba [2] be bb [2] a5 bd [2] b9 ba [2] a5 95 }

  condition:
    any of them
}