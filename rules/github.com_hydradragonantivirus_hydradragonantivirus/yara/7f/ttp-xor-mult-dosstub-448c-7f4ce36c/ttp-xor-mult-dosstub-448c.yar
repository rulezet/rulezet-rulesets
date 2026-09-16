rule TTP_XOR_MULT_DOSStub_448c {
  strings:
    $key_448c = { 10 e4 [2] 64 fc [2] 23 fe [2] 64 ef [2] 2a e3 [2] 26 e9 [2] 31 e2 [2] 2a ac [2] 17 }

  condition:
    any of them
}