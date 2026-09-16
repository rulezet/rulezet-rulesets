rule TTP_XOR_MULT_DOSStub_8339 {
  strings:
    $key_8339 = { d7 51 [2] a3 49 [2] e4 4b [2] a3 5a [2] ed 56 [2] e1 5c [2] f6 57 [2] ed 19 [2] d0 }

  condition:
    any of them
}