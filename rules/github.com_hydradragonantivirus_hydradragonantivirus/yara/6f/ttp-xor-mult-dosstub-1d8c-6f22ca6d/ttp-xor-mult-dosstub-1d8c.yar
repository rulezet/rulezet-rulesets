rule TTP_XOR_MULT_DOSStub_1d8c {
  strings:
    $key_1d8c = { 49 e4 [2] 3d fc [2] 7a fe [2] 3d ef [2] 73 e3 [2] 7f e9 [2] 68 e2 [2] 73 ac [2] 4e }

  condition:
    any of them
}