rule TTP_XOR_QUAD_CurrentVersionRun_8cec {
  strings:
    $key_8cec = { df 83 [2] fb 8d [2] d0 a1 [2] fe 83 [2] ea 98 [2] e5 82 [2] fb 9f [2] f9 9e [2] e2 98 [2] fe 9f [2] e2 b0 }

  condition:
    any of them
}