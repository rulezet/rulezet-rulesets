rule TTP_XOR_MULT_DOSStub_738c {
  strings:
    $key_738c = { 27 e4 [2] 53 fc [2] 14 fe [2] 53 ef [2] 1d e3 [2] 11 e9 [2] 06 e2 [2] 1d ac [2] 20 }

  condition:
    any of them
}