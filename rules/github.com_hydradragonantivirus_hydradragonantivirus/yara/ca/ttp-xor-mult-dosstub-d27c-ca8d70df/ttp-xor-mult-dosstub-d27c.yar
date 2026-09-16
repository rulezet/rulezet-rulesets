rule TTP_XOR_MULT_DOSStub_d27c {
  strings:
    $key_d27c = { 86 14 [2] f2 0c [2] b5 0e [2] f2 1f [2] bc 13 [2] b0 19 [2] a7 12 [2] bc 5c [2] 81 }

  condition:
    any of them
}