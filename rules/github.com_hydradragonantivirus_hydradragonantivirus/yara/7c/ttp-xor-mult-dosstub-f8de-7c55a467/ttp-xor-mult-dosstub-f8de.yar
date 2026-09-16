rule TTP_XOR_MULT_DOSStub_f8de {
  strings:
    $key_f8de = { ac b6 [2] d8 ae [2] 9f ac [2] d8 bd [2] 96 b1 [2] 9a bb [2] 8d b0 [2] 96 fe [2] ab }

  condition:
    any of them
}