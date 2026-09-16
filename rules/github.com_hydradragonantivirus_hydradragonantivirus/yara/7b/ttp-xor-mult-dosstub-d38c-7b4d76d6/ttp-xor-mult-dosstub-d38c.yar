rule TTP_XOR_MULT_DOSStub_d38c {
  strings:
    $key_d38c = { 87 e4 [2] f3 fc [2] b4 fe [2] f3 ef [2] bd e3 [2] b1 e9 [2] a6 e2 [2] bd ac [2] 80 }

  condition:
    any of them
}