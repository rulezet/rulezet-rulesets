rule TTP_XOR_MULT_DOSStub_90f9 {
  strings:
    $key_90f9 = { c4 91 [2] b0 89 [2] f7 8b [2] b0 9a [2] fe 96 [2] f2 9c [2] e5 97 [2] fe d9 [2] c3 }

  condition:
    any of them
}