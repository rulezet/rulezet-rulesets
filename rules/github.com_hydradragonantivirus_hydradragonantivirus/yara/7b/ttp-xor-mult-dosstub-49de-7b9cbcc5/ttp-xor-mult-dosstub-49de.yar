rule TTP_XOR_MULT_DOSStub_49de {
  strings:
    $key_49de = { 1d b6 [2] 69 ae [2] 2e ac [2] 69 bd [2] 27 b1 [2] 2b bb [2] 3c b0 [2] 27 fe [2] 1a }

  condition:
    any of them
}