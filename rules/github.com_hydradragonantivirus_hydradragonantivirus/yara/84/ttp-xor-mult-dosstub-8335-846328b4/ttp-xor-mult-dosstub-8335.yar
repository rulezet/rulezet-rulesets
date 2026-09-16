rule TTP_XOR_MULT_DOSStub_8335 {
  strings:
    $key_8335 = { d7 5d [2] a3 45 [2] e4 47 [2] a3 56 [2] ed 5a [2] e1 50 [2] f6 5b [2] ed 15 [2] d0 }

  condition:
    any of them
}