rule TTP_XOR_MULT_DOSStub_deee {
  strings:
    $key_deee = { 8a 86 [2] fe 9e [2] b9 9c [2] fe 8d [2] b0 81 [2] bc 8b [2] ab 80 [2] b0 ce [2] 8d }

  condition:
    any of them
}