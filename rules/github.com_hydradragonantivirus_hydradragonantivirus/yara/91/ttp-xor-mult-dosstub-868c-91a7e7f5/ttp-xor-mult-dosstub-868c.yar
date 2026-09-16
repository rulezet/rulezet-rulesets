rule TTP_XOR_MULT_DOSStub_868c {
  strings:
    $key_868c = { d2 e4 [2] a6 fc [2] e1 fe [2] a6 ef [2] e8 e3 [2] e4 e9 [2] f3 e2 [2] e8 ac [2] d5 }

  condition:
    any of them
}