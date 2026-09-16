rule TTP_XOR_QUAD_CurrentVersionRun_8c60 {
  strings:
    $key_8c60 = { df 0f [2] fb 01 [2] d0 2d [2] fe 0f [2] ea 14 [2] e5 0e [2] fb 13 [2] f9 12 [2] e2 14 [2] fe 13 [2] e2 3c }

  condition:
    any of them
}