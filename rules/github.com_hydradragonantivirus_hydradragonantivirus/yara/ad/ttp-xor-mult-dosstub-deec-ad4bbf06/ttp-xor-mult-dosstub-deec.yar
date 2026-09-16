rule TTP_XOR_MULT_DOSStub_deec {
  strings:
    $key_deec = { 8a 84 [2] fe 9c [2] b9 9e [2] fe 8f [2] b0 83 [2] bc 89 [2] ab 82 [2] b0 cc [2] 8d }

  condition:
    any of them
}