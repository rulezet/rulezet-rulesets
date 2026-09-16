rule TTP_XOR_MULT_DOSStub_838c {
  strings:
    $key_838c = { d7 e4 [2] a3 fc [2] e4 fe [2] a3 ef [2] ed e3 [2] e1 e9 [2] f6 e2 [2] ed ac [2] d0 }

  condition:
    any of them
}