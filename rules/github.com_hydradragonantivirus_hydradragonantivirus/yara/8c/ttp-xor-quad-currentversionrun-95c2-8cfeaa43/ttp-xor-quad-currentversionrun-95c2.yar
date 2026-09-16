rule TTP_XOR_QUAD_CurrentVersionRun_95c2 {
  strings:
    $key_95c2 = { c6 ad [2] e2 a3 [2] c9 8f [2] e7 ad [2] f3 b6 [2] fc ac [2] e2 b1 [2] e0 b0 [2] fb b6 [2] e7 b1 [2] fb 9e }

  condition:
    any of them
}