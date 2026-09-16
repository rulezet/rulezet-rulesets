rule TTP_XOR_MULT_DOSStub_f68c {
  strings:
    $key_f68c = { a2 e4 [2] d6 fc [2] 91 fe [2] d6 ef [2] 98 e3 [2] 94 e9 [2] 83 e2 [2] 98 ac [2] a5 }

  condition:
    any of them
}