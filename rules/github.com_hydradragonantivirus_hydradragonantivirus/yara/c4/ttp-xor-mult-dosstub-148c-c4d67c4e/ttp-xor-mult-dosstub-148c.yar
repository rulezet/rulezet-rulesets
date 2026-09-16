rule TTP_XOR_MULT_DOSStub_148c {
  strings:
    $key_148c = { 40 e4 [2] 34 fc [2] 73 fe [2] 34 ef [2] 7a e3 [2] 76 e9 [2] 61 e2 [2] 7a ac [2] 47 }

  condition:
    any of them
}