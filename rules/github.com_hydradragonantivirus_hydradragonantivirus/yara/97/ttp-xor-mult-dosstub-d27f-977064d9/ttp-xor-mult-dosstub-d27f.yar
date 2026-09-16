rule TTP_XOR_MULT_DOSStub_d27f {
  strings:
    $key_d27f = { 86 17 [2] f2 0f [2] b5 0d [2] f2 1c [2] bc 10 [2] b0 1a [2] a7 11 [2] bc 5f [2] 81 }

  condition:
    any of them
}