rule TTP_XOR_MULT_DOSStub_f78c {
  strings:
    $key_f78c = { a3 e4 [2] d7 fc [2] 90 fe [2] d7 ef [2] 99 e3 [2] 95 e9 [2] 82 e2 [2] 99 ac [2] a4 }

  condition:
    any of them
}