rule TTP_XOR_MULT_DOSStub_858c {
  strings:
    $key_858c = { d1 e4 [2] a5 fc [2] e2 fe [2] a5 ef [2] eb e3 [2] e7 e9 [2] f0 e2 [2] eb ac [2] d6 }

  condition:
    any of them
}