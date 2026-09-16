rule TTP_XOR_QUAD_CurrentVersionRun_8ce3 {
  strings:
    $key_8ce3 = { df 8c [2] fb 82 [2] d0 ae [2] fe 8c [2] ea 97 [2] e5 8d [2] fb 90 [2] f9 91 [2] e2 97 [2] fe 90 [2] e2 bf }

  condition:
    any of them
}