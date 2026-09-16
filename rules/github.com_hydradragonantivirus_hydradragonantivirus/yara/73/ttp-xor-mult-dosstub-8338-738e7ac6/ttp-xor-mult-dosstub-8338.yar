rule TTP_XOR_MULT_DOSStub_8338 {
  strings:
    $key_8338 = { d7 50 [2] a3 48 [2] e4 4a [2] a3 5b [2] ed 57 [2] e1 5d [2] f6 56 [2] ed 18 [2] d0 }

  condition:
    any of them
}