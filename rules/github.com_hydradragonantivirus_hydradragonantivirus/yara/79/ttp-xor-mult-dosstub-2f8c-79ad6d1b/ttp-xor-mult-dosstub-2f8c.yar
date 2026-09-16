rule TTP_XOR_MULT_DOSStub_2f8c {
  strings:
    $key_2f8c = { 7b e4 [2] 0f fc [2] 48 fe [2] 0f ef [2] 41 e3 [2] 4d e9 [2] 5a e2 [2] 41 ac [2] 7c }

  condition:
    any of them
}