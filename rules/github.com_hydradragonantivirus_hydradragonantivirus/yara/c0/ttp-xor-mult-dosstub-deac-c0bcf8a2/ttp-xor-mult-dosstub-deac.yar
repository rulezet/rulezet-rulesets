rule TTP_XOR_MULT_DOSStub_deac {
  strings:
    $key_deac = { 8a c4 [2] fe dc [2] b9 de [2] fe cf [2] b0 c3 [2] bc c9 [2] ab c2 [2] b0 8c [2] 8d }

  condition:
    any of them
}