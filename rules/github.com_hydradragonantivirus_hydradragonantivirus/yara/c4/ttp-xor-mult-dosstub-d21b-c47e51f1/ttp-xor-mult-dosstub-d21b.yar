rule TTP_XOR_MULT_DOSStub_d21b {
  strings:
    $key_d21b = { 86 73 [2] f2 6b [2] b5 69 [2] f2 78 [2] bc 74 [2] b0 7e [2] a7 75 [2] bc 3b [2] 81 }

  condition:
    any of them
}