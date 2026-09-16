rule TTP_XOR_MULT_DOSStub_6f8c {
  strings:
    $key_6f8c = { 3b e4 [2] 4f fc [2] 08 fe [2] 4f ef [2] 01 e3 [2] 0d e9 [2] 1a e2 [2] 01 ac [2] 3c }

  condition:
    any of them
}