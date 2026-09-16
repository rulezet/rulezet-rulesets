rule TTP_XOR_MULT_DOSStub_b18c {
  strings:
    $key_b18c = { e5 e4 [2] 91 fc [2] d6 fe [2] 91 ef [2] df e3 [2] d3 e9 [2] c4 e2 [2] df ac [2] e2 }

  condition:
    any of them
}