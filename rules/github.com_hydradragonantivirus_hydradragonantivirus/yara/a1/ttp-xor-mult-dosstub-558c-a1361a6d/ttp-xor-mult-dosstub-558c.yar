rule TTP_XOR_MULT_DOSStub_558c {
  strings:
    $key_558c = { 01 e4 [2] 75 fc [2] 32 fe [2] 75 ef [2] 3b e3 [2] 37 e9 [2] 20 e2 [2] 3b ac [2] 06 }

  condition:
    any of them
}