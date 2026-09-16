rule TTP_XOR_MULT_DOSStub_da8a {
  strings:
    $key_da8a = { 8e e2 [2] fa fa [2] bd f8 [2] fa e9 [2] b4 e5 [2] b8 ef [2] af e4 [2] b4 aa [2] 89 }

  condition:
    any of them
}