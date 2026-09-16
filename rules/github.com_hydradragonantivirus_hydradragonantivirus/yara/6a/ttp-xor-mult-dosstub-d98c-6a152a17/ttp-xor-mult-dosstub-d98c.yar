rule TTP_XOR_MULT_DOSStub_d98c {
  strings:
    $key_d98c = { 8d e4 [2] f9 fc [2] be fe [2] f9 ef [2] b7 e3 [2] bb e9 [2] ac e2 [2] b7 ac [2] 8a }

  condition:
    any of them
}