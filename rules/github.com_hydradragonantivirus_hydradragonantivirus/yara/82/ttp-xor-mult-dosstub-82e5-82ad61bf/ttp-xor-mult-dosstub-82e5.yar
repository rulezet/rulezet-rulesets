rule TTP_XOR_MULT_DOSStub_82e5 {
  strings:
    $key_82e5 = { d6 8d [2] a2 95 [2] e5 97 [2] a2 86 [2] ec 8a [2] e0 80 [2] f7 8b [2] ec c5 [2] d1 }

  condition:
    any of them
}