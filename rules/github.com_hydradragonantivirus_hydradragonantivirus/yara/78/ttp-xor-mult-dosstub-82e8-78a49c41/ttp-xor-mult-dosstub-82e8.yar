rule TTP_XOR_MULT_DOSStub_82e8 {
  strings:
    $key_82e8 = { d6 80 [2] a2 98 [2] e5 9a [2] a2 8b [2] ec 87 [2] e0 8d [2] f7 86 [2] ec c8 [2] d1 }

  condition:
    any of them
}