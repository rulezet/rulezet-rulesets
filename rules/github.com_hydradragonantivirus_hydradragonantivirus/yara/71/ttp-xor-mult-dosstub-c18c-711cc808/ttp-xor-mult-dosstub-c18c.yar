rule TTP_XOR_MULT_DOSStub_c18c {
  strings:
    $key_c18c = { 95 e4 [2] e1 fc [2] a6 fe [2] e1 ef [2] af e3 [2] a3 e9 [2] b4 e2 [2] af ac [2] 92 }

  condition:
    any of them
}