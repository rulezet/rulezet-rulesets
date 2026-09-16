rule TTP_XOR_MULT_DOSStub_d22c {
  strings:
    $key_d22c = { 86 44 [2] f2 5c [2] b5 5e [2] f2 4f [2] bc 43 [2] b0 49 [2] a7 42 [2] bc 0c [2] 81 }

  condition:
    any of them
}