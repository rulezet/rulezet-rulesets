rule TTP_XOR_QUAD_CurrentVersionRun_95fd {
  strings:
    $key_95fd = { c6 92 [2] e2 9c [2] c9 b0 [2] e7 92 [2] f3 89 [2] fc 93 [2] e2 8e [2] e0 8f [2] fb 89 [2] e7 8e [2] fb a1 }

  condition:
    any of them
}