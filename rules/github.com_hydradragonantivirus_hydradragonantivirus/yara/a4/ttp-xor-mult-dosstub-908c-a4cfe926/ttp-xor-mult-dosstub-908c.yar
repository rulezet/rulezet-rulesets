rule TTP_XOR_MULT_DOSStub_908c {
  strings:
    $key_908c = { c4 e4 [2] b0 fc [2] f7 fe [2] b0 ef [2] fe e3 [2] f2 e9 [2] e5 e2 [2] fe ac [2] c3 }

  condition:
    any of them
}