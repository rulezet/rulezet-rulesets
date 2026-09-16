rule TTP_XOR_MULT_DOSStub_82e2 {
  strings:
    $key_82e2 = { d6 8a [2] a2 92 [2] e5 90 [2] a2 81 [2] ec 8d [2] e0 87 [2] f7 8c [2] ec c2 [2] d1 }

  condition:
    any of them
}