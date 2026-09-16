rule TTP_XOR_MULT_DOSStub_9e8c {
  strings:
    $key_9e8c = { ca e4 [2] be fc [2] f9 fe [2] be ef [2] f0 e3 [2] fc e9 [2] eb e2 [2] f0 ac [2] cd }

  condition:
    any of them
}