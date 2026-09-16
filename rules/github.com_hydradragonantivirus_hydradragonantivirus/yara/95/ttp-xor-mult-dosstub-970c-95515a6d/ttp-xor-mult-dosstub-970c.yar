rule TTP_XOR_MULT_DOSStub_970c {
  strings:
    $key_970c = { c3 64 [2] b7 7c [2] f0 7e [2] b7 6f [2] f9 63 [2] f5 69 [2] e2 62 [2] f9 2c [2] c4 }

  condition:
    any of them
}