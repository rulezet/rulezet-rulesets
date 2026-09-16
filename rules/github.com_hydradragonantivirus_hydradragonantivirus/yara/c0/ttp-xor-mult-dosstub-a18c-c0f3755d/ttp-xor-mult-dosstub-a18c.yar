rule TTP_XOR_MULT_DOSStub_a18c {
  strings:
    $key_a18c = { f5 e4 [2] 81 fc [2] c6 fe [2] 81 ef [2] cf e3 [2] c3 e9 [2] d4 e2 [2] cf ac [2] f2 }

  condition:
    any of them
}