rule TTP_XOR_MULT_DOSStub_578c {
  strings:
    $key_578c = { 03 e4 [2] 77 fc [2] 30 fe [2] 77 ef [2] 39 e3 [2] 35 e9 [2] 22 e2 [2] 39 ac [2] 04 }

  condition:
    any of them
}