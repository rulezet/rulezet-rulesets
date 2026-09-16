rule TTP_XOR_MULT_DOSStub_348c {
  strings:
    $key_348c = { 60 e4 [2] 14 fc [2] 53 fe [2] 14 ef [2] 5a e3 [2] 56 e9 [2] 41 e2 [2] 5a ac [2] 67 }

  condition:
    any of them
}