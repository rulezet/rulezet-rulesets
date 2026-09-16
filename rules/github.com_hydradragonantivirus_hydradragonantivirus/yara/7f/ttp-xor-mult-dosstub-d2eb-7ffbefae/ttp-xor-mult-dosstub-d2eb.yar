rule TTP_XOR_MULT_DOSStub_d2eb {
  strings:
    $key_d2eb = { 86 83 [2] f2 9b [2] b5 99 [2] f2 88 [2] bc 84 [2] b0 8e [2] a7 85 [2] bc cb [2] 81 }

  condition:
    any of them
}