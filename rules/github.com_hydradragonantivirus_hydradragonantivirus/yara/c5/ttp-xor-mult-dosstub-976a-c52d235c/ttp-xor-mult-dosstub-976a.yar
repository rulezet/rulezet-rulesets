rule TTP_XOR_MULT_DOSStub_976a {
  strings:
    $key_976a = { c3 02 [2] b7 1a [2] f0 18 [2] b7 09 [2] f9 05 [2] f5 0f [2] e2 04 [2] f9 4a [2] c4 }

  condition:
    any of them
}