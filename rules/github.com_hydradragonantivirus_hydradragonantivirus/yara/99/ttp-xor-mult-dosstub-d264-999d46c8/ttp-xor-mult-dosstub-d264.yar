rule TTP_XOR_MULT_DOSStub_d264 {
  strings:
    $key_d264 = { 86 0c [2] f2 14 [2] b5 16 [2] f2 07 [2] bc 0b [2] b0 01 [2] a7 0a [2] bc 44 [2] 81 }

  condition:
    any of them
}