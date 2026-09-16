rule TTP_XOR_MULT_DOSStub_728c {
  strings:
    $key_728c = { 26 e4 [2] 52 fc [2] 15 fe [2] 52 ef [2] 1c e3 [2] 10 e9 [2] 07 e2 [2] 1c ac [2] 21 }

  condition:
    any of them
}