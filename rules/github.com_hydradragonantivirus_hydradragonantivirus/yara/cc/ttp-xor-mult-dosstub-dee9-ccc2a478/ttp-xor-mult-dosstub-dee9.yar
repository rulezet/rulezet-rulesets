rule TTP_XOR_MULT_DOSStub_dee9 {
  strings:
    $key_dee9 = { 8a 81 [2] fe 99 [2] b9 9b [2] fe 8a [2] b0 86 [2] bc 8c [2] ab 87 [2] b0 c9 [2] 8d }

  condition:
    any of them
}