rule TTP_XOR_QUAD_CurrentVersionRun_8c30 {
  strings:
    $key_8c30 = { df 5f [2] fb 51 [2] d0 7d [2] fe 5f [2] ea 44 [2] e5 5e [2] fb 43 [2] f9 42 [2] e2 44 [2] fe 43 [2] e2 6c }

  condition:
    any of them
}