rule TTP_XOR_MULT_DOSStub_d28a {
  strings:
    $key_d28a = { 86 e2 [2] f2 fa [2] b5 f8 [2] f2 e9 [2] bc e5 [2] b0 ef [2] a7 e4 [2] bc aa [2] 81 }

  condition:
    any of them
}