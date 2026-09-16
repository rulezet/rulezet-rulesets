rule TTP_XOR_MULT_DOSStub_830c {
  strings:
    $key_830c = { d7 64 [2] a3 7c [2] e4 7e [2] a3 6f [2] ed 63 [2] e1 69 [2] f6 62 [2] ed 2c [2] d0 }

  condition:
    any of them
}