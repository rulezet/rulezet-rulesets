rule TTP_XOR_MULT_DOSStub_378e {
  strings:
    $key_378e = { 63 e6 [2] 17 fe [2] 50 fc [2] 17 ed [2] 59 e1 [2] 55 eb [2] 42 e0 [2] 59 ae [2] 64 }

  condition:
    any of them
}