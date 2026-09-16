rule TTP_XOR_MULT_DOSStub_11de {
  strings:
    $key_11de = { 45 b6 [2] 31 ae [2] 76 ac [2] 31 bd [2] 7f b1 [2] 73 bb [2] 64 b0 [2] 7f fe [2] 42 }

  condition:
    any of them
}