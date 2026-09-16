rule TTP_XOR_MULT_DOSStub_3f8c {
  strings:
    $key_3f8c = { 6b e4 [2] 1f fc [2] 58 fe [2] 1f ef [2] 51 e3 [2] 5d e9 [2] 4a e2 [2] 51 ac [2] 6c }

  condition:
    any of them
}