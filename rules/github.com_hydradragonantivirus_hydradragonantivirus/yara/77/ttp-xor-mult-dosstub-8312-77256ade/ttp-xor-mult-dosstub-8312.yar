rule TTP_XOR_MULT_DOSStub_8312 {
  strings:
    $key_8312 = { d7 7a [2] a3 62 [2] e4 60 [2] a3 71 [2] ed 7d [2] e1 77 [2] f6 7c [2] ed 32 [2] d0 }

  condition:
    any of them
}