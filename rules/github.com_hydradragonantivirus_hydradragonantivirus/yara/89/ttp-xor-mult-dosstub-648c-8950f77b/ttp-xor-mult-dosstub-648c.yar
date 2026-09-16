rule TTP_XOR_MULT_DOSStub_648c {
  strings:
    $key_648c = { 30 e4 [2] 44 fc [2] 03 fe [2] 44 ef [2] 0a e3 [2] 06 e9 [2] 11 e2 [2] 0a ac [2] 37 }

  condition:
    any of them
}