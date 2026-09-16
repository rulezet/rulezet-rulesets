rule TTP_XOR_MULT_DOSStub_ca8c {
  strings:
    $key_ca8c = { 9e e4 [2] ea fc [2] ad fe [2] ea ef [2] a4 e3 [2] a8 e9 [2] bf e2 [2] a4 ac [2] 99 }

  condition:
    any of them
}