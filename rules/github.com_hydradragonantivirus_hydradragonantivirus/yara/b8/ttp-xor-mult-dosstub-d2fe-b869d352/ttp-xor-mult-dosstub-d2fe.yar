rule TTP_XOR_MULT_DOSStub_d2fe {
  strings:
    $key_d2fe = { 86 96 [2] f2 8e [2] b5 8c [2] f2 9d [2] bc 91 [2] b0 9b [2] a7 90 [2] bc de [2] 81 }

  condition:
    any of them
}