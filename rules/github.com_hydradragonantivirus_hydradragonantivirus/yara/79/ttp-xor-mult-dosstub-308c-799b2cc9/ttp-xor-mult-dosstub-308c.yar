rule TTP_XOR_MULT_DOSStub_308c {
  strings:
    $key_308c = { 64 e4 [2] 10 fc [2] 57 fe [2] 10 ef [2] 5e e3 [2] 52 e9 [2] 45 e2 [2] 5e ac [2] 63 }

  condition:
    any of them
}