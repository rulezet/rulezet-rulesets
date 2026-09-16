rule TTP_XOR_MULT_DOSStub_d26c {
  strings:
    $key_d26c = { 86 04 [2] f2 1c [2] b5 1e [2] f2 0f [2] bc 03 [2] b0 09 [2] a7 02 [2] bc 4c [2] 81 }

  condition:
    any of them
}