rule TTP_XOR_QUAD_CurrentVersionRun_952a {
  strings:
    $key_952a = { c6 45 [2] e2 4b [2] c9 67 [2] e7 45 [2] f3 5e [2] fc 44 [2] e2 59 [2] e0 58 [2] fb 5e [2] e7 59 [2] fb 76 }

  condition:
    any of them
}