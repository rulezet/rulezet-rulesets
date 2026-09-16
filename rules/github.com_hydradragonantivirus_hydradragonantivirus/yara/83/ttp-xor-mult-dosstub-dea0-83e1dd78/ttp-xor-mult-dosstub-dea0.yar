rule TTP_XOR_MULT_DOSStub_dea0 {
  strings:
    $key_dea0 = { 8a c8 [2] fe d0 [2] b9 d2 [2] fe c3 [2] b0 cf [2] bc c5 [2] ab ce [2] b0 80 [2] 8d }

  condition:
    any of them
}