rule TTP_XOR_QUAD_CurrentVersionRun_9520 {
  strings:
    $key_9520 = { c6 4f [2] e2 41 [2] c9 6d [2] e7 4f [2] f3 54 [2] fc 4e [2] e2 53 [2] e0 52 [2] fb 54 [2] e7 53 [2] fb 7c }

  condition:
    any of them
}