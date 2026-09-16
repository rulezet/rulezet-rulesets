rule TTP_XOR_MULT_DOSStub_dc8a {
  strings:
    $key_dc8a = { 88 e2 [2] fc fa [2] bb f8 [2] fc e9 [2] b2 e5 [2] be ef [2] a9 e4 [2] b2 aa [2] 8f }

  condition:
    any of them
}