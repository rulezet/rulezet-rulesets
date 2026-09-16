rule TTP_XOR_MULT_DOSStub_958c {
  strings:
    $key_958c = { c1 e4 [2] b5 fc [2] f2 fe [2] b5 ef [2] fb e3 [2] f7 e9 [2] e0 e2 [2] fb ac [2] c6 }

  condition:
    any of them
}