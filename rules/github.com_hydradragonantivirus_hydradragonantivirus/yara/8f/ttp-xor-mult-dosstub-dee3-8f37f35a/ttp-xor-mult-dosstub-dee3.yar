rule TTP_XOR_MULT_DOSStub_dee3 {
  strings:
    $key_dee3 = { 8a 8b [2] fe 93 [2] b9 91 [2] fe 80 [2] b0 8c [2] bc 86 [2] ab 8d [2] b0 c3 [2] 8d }

  condition:
    any of them
}