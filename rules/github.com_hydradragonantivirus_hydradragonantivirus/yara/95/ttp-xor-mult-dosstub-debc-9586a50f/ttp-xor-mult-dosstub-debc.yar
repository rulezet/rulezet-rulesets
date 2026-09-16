rule TTP_XOR_MULT_DOSStub_debc {
  strings:
    $key_debc = { 8a d4 [2] fe cc [2] b9 ce [2] fe df [2] b0 d3 [2] bc d9 [2] ab d2 [2] b0 9c [2] 8d }

  condition:
    any of them
}