rule TTP_XOR_MULT_DOSStub_18de {
  strings:
    $key_18de = { 4c b6 [2] 38 ae [2] 7f ac [2] 38 bd [2] 76 b1 [2] 7a bb [2] 6d b0 [2] 76 fe [2] 4b }

  condition:
    any of them
}