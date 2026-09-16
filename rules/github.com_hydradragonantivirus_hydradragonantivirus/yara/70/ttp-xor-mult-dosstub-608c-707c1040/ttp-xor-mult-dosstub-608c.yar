rule TTP_XOR_MULT_DOSStub_608c {
  strings:
    $key_608c = { 34 e4 [2] 40 fc [2] 07 fe [2] 40 ef [2] 0e e3 [2] 02 e9 [2] 15 e2 [2] 0e ac [2] 33 }

  condition:
    any of them
}