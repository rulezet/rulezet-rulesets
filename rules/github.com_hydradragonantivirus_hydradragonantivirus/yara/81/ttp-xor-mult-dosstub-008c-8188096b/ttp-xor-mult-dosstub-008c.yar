rule TTP_XOR_MULT_DOSStub_008c {
  strings:
    $key_008c = { 54 e4 [2] 20 fc [2] 67 fe [2] 20 ef [2] 6e e3 [2] 62 e9 [2] 75 e2 [2] 6e ac [2] 53 }

  condition:
    any of them
}