rule TTP_XOR_MULT_DOSStub_38de {
  strings:
    $key_38de = { 6c b6 [2] 18 ae [2] 5f ac [2] 18 bd [2] 56 b1 [2] 5a bb [2] 4d b0 [2] 56 fe [2] 6b }

  condition:
    any of them
}