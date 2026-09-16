rule TTP_XOR_MULT_DOSStub_d2ec {
  strings:
    $key_d2ec = { 86 84 [2] f2 9c [2] b5 9e [2] f2 8f [2] bc 83 [2] b0 89 [2] a7 82 [2] bc cc [2] 81 }

  condition:
    any of them
}