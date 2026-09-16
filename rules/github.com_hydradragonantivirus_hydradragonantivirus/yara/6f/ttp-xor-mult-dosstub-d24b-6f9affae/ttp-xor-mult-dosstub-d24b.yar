rule TTP_XOR_MULT_DOSStub_d24b {
  strings:
    $key_d24b = { 86 23 [2] f2 3b [2] b5 39 [2] f2 28 [2] bc 24 [2] b0 2e [2] a7 25 [2] bc 6b [2] 81 }

  condition:
    any of them
}