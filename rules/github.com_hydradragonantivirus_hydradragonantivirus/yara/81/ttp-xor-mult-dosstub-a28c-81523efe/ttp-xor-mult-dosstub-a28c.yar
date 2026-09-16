rule TTP_XOR_MULT_DOSStub_a28c {
  strings:
    $key_a28c = { f6 e4 [2] 82 fc [2] c5 fe [2] 82 ef [2] cc e3 [2] c0 e9 [2] d7 e2 [2] cc ac [2] f1 }

  condition:
    any of them
}