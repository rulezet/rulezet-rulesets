rule TTP_XOR_MULT_DOSStub_b38c {
  strings:
    $key_b38c = { e7 e4 [2] 93 fc [2] d4 fe [2] 93 ef [2] dd e3 [2] d1 e9 [2] c6 e2 [2] dd ac [2] e0 }

  condition:
    any of them
}