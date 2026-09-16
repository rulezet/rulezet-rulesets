rule TTP_XOR_MULT_DOSStub_0d8c {
  strings:
    $key_0d8c = { 59 e4 [2] 2d fc [2] 6a fe [2] 2d ef [2] 63 e3 [2] 6f e9 [2] 78 e2 [2] 63 ac [2] 5e }

  condition:
    any of them
}