rule TTP_XOR_MULT_DOSStub_108c {
  strings:
    $key_108c = { 44 e4 [2] 30 fc [2] 77 fe [2] 30 ef [2] 7e e3 [2] 72 e9 [2] 65 e2 [2] 7e ac [2] 43 }

  condition:
    any of them
}