rule TTP_XOR_MULT_DOSStub_defd {
  strings:
    $key_defd = { 8a 95 [2] fe 8d [2] b9 8f [2] fe 9e [2] b0 92 [2] bc 98 [2] ab 93 [2] b0 dd [2] 8d }

  condition:
    any of them
}