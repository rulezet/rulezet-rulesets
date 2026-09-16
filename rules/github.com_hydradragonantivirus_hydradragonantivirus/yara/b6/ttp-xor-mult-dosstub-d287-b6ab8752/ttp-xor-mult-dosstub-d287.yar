rule TTP_XOR_MULT_DOSStub_d287 {
  strings:
    $key_d287 = { 86 ef [2] f2 f7 [2] b5 f5 [2] f2 e4 [2] bc e8 [2] b0 e2 [2] a7 e9 [2] bc a7 [2] 81 }

  condition:
    any of them
}