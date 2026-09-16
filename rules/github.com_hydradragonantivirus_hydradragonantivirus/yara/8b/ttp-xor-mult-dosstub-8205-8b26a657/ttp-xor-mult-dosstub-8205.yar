rule TTP_XOR_MULT_DOSStub_8205 {
  strings:
    $key_8205 = { d6 6d [2] a2 75 [2] e5 77 [2] a2 66 [2] ec 6a [2] e0 60 [2] f7 6b [2] ec 25 [2] d1 }

  condition:
    any of them
}