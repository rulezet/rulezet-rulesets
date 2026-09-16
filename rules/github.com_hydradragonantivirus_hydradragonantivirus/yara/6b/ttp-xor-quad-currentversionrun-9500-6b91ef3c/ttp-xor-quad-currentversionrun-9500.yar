rule TTP_XOR_QUAD_CurrentVersionRun_9500 {
  strings:
    $key_9500 = { c6 6f [2] e2 61 [2] c9 4d [2] e7 6f [2] f3 74 [2] fc 6e [2] e2 73 [2] e0 72 [2] fb 74 [2] e7 73 [2] fb 5c }

  condition:
    any of them
}