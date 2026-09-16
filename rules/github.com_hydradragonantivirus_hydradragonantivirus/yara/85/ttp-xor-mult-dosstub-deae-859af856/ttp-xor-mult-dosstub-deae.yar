rule TTP_XOR_MULT_DOSStub_deae {
  strings:
    $key_deae = { 8a c6 [2] fe de [2] b9 dc [2] fe cd [2] b0 c1 [2] bc cb [2] ab c0 [2] b0 8e [2] 8d }

  condition:
    any of them
}