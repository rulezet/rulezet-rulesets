rule TTP_XOR_MULT_DOSStub_dee8 {
  strings:
    $key_dee8 = { 8a 80 [2] fe 98 [2] b9 9a [2] fe 8b [2] b0 87 [2] bc 8d [2] ab 86 [2] b0 c8 [2] 8d }

  condition:
    any of them
}