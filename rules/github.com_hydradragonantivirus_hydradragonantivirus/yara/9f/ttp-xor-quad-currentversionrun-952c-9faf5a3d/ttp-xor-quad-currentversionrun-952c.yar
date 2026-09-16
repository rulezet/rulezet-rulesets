rule TTP_XOR_QUAD_CurrentVersionRun_952c {
  strings:
    $key_952c = { c6 43 [2] e2 4d [2] c9 61 [2] e7 43 [2] f3 58 [2] fc 42 [2] e2 5f [2] e0 5e [2] fb 58 [2] e7 5f [2] fb 70 }

  condition:
    any of them
}