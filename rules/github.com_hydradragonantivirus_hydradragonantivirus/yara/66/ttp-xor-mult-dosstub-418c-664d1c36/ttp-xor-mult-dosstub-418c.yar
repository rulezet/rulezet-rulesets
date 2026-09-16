rule TTP_XOR_MULT_DOSStub_418c {
  strings:
    $key_418c = { 15 e4 [2] 61 fc [2] 26 fe [2] 61 ef [2] 2f e3 [2] 23 e9 [2] 34 e2 [2] 2f ac [2] 12 }

  condition:
    any of them
}