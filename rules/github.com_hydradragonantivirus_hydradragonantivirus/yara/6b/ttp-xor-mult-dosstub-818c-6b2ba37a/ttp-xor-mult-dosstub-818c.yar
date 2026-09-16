rule TTP_XOR_MULT_DOSStub_818c {
  strings:
    $key_818c = { d5 e4 [2] a1 fc [2] e6 fe [2] a1 ef [2] ef e3 [2] e3 e9 [2] f4 e2 [2] ef ac [2] d2 }

  condition:
    any of them
}