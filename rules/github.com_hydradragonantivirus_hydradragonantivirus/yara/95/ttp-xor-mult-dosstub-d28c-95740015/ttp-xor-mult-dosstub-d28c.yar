rule TTP_XOR_MULT_DOSStub_d28c {
  strings:
    $key_d28c = { 86 e4 [2] f2 fc [2] b5 fe [2] f2 ef [2] bc e3 [2] b0 e9 [2] a7 e2 [2] bc ac [2] 81 }

  condition:
    any of them
}