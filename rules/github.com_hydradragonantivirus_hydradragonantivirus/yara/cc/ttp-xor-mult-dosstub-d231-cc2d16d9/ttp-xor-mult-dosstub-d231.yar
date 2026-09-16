rule TTP_XOR_MULT_DOSStub_d231 {
  strings:
    $key_d231 = { 86 59 [2] f2 41 [2] b5 43 [2] f2 52 [2] bc 5e [2] b0 54 [2] a7 5f [2] bc 11 [2] 81 }

  condition:
    any of them
}