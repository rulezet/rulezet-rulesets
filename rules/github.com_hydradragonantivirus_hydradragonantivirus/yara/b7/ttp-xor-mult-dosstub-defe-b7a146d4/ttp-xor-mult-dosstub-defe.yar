rule TTP_XOR_MULT_DOSStub_defe {
  strings:
    $key_defe = { 8a 96 [2] fe 8e [2] b9 8c [2] fe 9d [2] b0 91 [2] bc 9b [2] ab 90 [2] b0 de [2] 8d }

  condition:
    any of them
}