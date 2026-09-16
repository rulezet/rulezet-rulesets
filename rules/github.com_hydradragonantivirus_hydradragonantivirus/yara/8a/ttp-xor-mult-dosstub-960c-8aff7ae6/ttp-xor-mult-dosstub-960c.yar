rule TTP_XOR_MULT_DOSStub_960c {
  strings:
    $key_960c = { c2 64 [2] b6 7c [2] f1 7e [2] b6 6f [2] f8 63 [2] f4 69 [2] e3 62 [2] f8 2c [2] c5 }

  condition:
    any of them
}