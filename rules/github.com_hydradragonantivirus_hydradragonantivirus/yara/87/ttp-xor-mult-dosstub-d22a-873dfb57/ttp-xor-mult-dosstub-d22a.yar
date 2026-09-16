rule TTP_XOR_MULT_DOSStub_d22a {
  strings:
    $key_d22a = { 86 42 [2] f2 5a [2] b5 58 [2] f2 49 [2] bc 45 [2] b0 4f [2] a7 44 [2] bc 0a [2] 81 }

  condition:
    any of them
}