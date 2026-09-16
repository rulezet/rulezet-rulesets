rule TTP_XOR_MULT_DOSStub_d203 {
  strings:
    $key_d203 = { 86 6b [2] f2 73 [2] b5 71 [2] f2 60 [2] bc 6c [2] b0 66 [2] a7 6d [2] bc 23 [2] 81 }

  condition:
    any of them
}