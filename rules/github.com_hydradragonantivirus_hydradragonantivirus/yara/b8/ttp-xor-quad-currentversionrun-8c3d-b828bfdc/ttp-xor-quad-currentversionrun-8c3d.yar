rule TTP_XOR_QUAD_CurrentVersionRun_8c3d {
  strings:
    $key_8c3d = { df 52 [2] fb 5c [2] d0 70 [2] fe 52 [2] ea 49 [2] e5 53 [2] fb 4e [2] f9 4f [2] e2 49 [2] fe 4e [2] e2 61 }

  condition:
    any of them
}