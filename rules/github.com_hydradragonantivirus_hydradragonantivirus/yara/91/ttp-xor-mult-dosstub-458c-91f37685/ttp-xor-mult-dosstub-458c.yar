rule TTP_XOR_MULT_DOSStub_458c {
  strings:
    $key_458c = { 11 e4 [2] 65 fc [2] 22 fe [2] 65 ef [2] 2b e3 [2] 27 e9 [2] 30 e2 [2] 2b ac [2] 16 }

  condition:
    any of them
}