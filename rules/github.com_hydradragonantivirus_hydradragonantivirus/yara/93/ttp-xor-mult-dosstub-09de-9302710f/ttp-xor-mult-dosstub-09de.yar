rule TTP_XOR_MULT_DOSStub_09de {
  strings:
    $key_09de = { 5d b6 [2] 29 ae [2] 6e ac [2] 29 bd [2] 67 b1 [2] 6b bb [2] 7c b0 [2] 67 fe [2] 5a }

  condition:
    any of them
}