rule TTP_XOR_MULT_DOSStub_e372 {
  strings:
    $key_e372 = { b7 1a [2] c3 02 [2] 84 00 [2] c3 11 [2] 8d 1d [2] 81 17 [2] 96 1c [2] 8d 52 [2] b0 }

  condition:
    any of them
}