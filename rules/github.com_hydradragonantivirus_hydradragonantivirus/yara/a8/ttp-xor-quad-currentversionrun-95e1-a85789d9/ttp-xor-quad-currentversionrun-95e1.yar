rule TTP_XOR_QUAD_CurrentVersionRun_95e1 {
  strings:
    $key_95e1 = { c6 8e [2] e2 80 [2] c9 ac [2] e7 8e [2] f3 95 [2] fc 8f [2] e2 92 [2] e0 93 [2] fb 95 [2] e7 92 [2] fb bd }

  condition:
    any of them
}