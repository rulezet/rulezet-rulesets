rule TTP_XOR_MULT_DOSStub_378c {
  strings:
    $key_378c = { 63 e4 [2] 17 fc [2] 50 fe [2] 17 ef [2] 59 e3 [2] 55 e9 [2] 42 e2 [2] 59 ac [2] 64 }

  condition:
    any of them
}