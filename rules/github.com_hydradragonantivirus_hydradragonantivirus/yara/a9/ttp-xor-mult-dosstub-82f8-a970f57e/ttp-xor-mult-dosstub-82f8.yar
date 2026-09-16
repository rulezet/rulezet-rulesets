rule TTP_XOR_MULT_DOSStub_82f8 {
  strings:
    $key_82f8 = { d6 90 [2] a2 88 [2] e5 8a [2] a2 9b [2] ec 97 [2] e0 9d [2] f7 96 [2] ec d8 [2] d1 }

  condition:
    any of them
}