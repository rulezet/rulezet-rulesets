rule TTP_XOR_MULT_DOSStub_138c {
  strings:
    $key_138c = { 47 e4 [2] 33 fc [2] 74 fe [2] 33 ef [2] 7d e3 [2] 71 e9 [2] 66 e2 [2] 7d ac [2] 40 }

  condition:
    any of them
}