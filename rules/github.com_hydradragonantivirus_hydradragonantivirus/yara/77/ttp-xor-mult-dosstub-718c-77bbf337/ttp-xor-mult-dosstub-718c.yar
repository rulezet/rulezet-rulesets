rule TTP_XOR_MULT_DOSStub_718c {
  strings:
    $key_718c = { 25 e4 [2] 51 fc [2] 16 fe [2] 51 ef [2] 1f e3 [2] 13 e9 [2] 04 e2 [2] 1f ac [2] 22 }

  condition:
    any of them
}