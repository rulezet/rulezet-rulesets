rule TTP_XOR_MULT_DOSStub_258c {
  strings:
    $key_258c = { 71 e4 [2] 05 fc [2] 42 fe [2] 05 ef [2] 4b e3 [2] 47 e9 [2] 50 e2 [2] 4b ac [2] 76 }

  condition:
    any of them
}