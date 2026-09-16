rule TTP_XOR_MULT_DOSStub_d29c {
  strings:
    $key_d29c = { 86 f4 [2] f2 ec [2] b5 ee [2] f2 ff [2] bc f3 [2] b0 f9 [2] a7 f2 [2] bc bc [2] 81 }

  condition:
    any of them
}