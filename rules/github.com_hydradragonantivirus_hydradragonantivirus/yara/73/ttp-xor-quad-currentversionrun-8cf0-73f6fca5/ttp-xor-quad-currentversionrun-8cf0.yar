rule TTP_XOR_QUAD_CurrentVersionRun_8cf0 {
  strings:
    $key_8cf0 = { df 9f [2] fb 91 [2] d0 bd [2] fe 9f [2] ea 84 [2] e5 9e [2] fb 83 [2] f9 82 [2] e2 84 [2] fe 83 [2] e2 ac }

  condition:
    any of them
}