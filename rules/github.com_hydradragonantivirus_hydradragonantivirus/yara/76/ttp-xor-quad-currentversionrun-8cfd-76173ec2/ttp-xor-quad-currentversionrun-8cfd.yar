rule TTP_XOR_QUAD_CurrentVersionRun_8cfd {
  strings:
    $key_8cfd = { df 92 [2] fb 9c [2] d0 b0 [2] fe 92 [2] ea 89 [2] e5 93 [2] fb 8e [2] f9 8f [2] e2 89 [2] fe 8e [2] e2 a1 }

  condition:
    any of them
}