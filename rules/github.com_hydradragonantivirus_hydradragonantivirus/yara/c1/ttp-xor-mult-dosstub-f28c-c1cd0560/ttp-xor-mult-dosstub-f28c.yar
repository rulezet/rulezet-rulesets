rule TTP_XOR_MULT_DOSStub_f28c {
  strings:
    $key_f28c = { a6 e4 [2] d2 fc [2] 95 fe [2] d2 ef [2] 9c e3 [2] 90 e9 [2] 87 e2 [2] 9c ac [2] a1 }

  condition:
    any of them
}