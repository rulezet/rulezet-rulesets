rule TTP_XOR_MULT_DOSStub_d21e {
  strings:
    $key_d21e = { 86 76 [2] f2 6e [2] b5 6c [2] f2 7d [2] bc 71 [2] b0 7b [2] a7 70 [2] bc 3e [2] 81 }

  condition:
    any of them
}