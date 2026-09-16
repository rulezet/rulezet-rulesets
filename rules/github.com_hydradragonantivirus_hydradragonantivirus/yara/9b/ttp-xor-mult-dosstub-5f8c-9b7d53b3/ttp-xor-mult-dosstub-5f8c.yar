rule TTP_XOR_MULT_DOSStub_5f8c {
  strings:
    $key_5f8c = { 0b e4 [2] 7f fc [2] 38 fe [2] 7f ef [2] 31 e3 [2] 3d e9 [2] 2a e2 [2] 31 ac [2] 0c }

  condition:
    any of them
}