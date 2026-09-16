rule TTP_XOR_MULT_DOSStub_e472 {
  strings:
    $key_e472 = { b0 1a [2] c4 02 [2] 83 00 [2] c4 11 [2] 8a 1d [2] 86 17 [2] 91 1c [2] 8a 52 [2] b7 }

  condition:
    any of them
}