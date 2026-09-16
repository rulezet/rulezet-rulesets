rule TTP_XOR_MULT_DOSStub_b68c {
  strings:
    $key_b68c = { e2 e4 [2] 96 fc [2] d1 fe [2] 96 ef [2] d8 e3 [2] d4 e9 [2] c3 e2 [2] d8 ac [2] e5 }

  condition:
    any of them
}