rule TTP_XOR_MULT_DOSStub_d267 {
  strings:
    $key_d267 = { 86 0f [2] f2 17 [2] b5 15 [2] f2 04 [2] bc 08 [2] b0 02 [2] a7 09 [2] bc 47 [2] 81 }

  condition:
    any of them
}