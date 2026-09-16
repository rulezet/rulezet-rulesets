rule TTP_XOR_MULT_DOSStub_8b9d {
  strings:
    $key_8b9d = { df f5 [2] ab ed [2] ec ef [2] ab fe [2] e5 f2 [2] e9 f8 [2] fe f3 [2] e5 bd [2] d8 }

  condition:
    any of them
}