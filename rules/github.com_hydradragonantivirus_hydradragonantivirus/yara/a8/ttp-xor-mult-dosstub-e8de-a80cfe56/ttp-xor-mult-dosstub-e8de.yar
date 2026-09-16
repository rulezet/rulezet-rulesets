rule TTP_XOR_MULT_DOSStub_e8de {
  strings:
    $key_e8de = { bc b6 [2] c8 ae [2] 8f ac [2] c8 bd [2] 86 b1 [2] 8a bb [2] 9d b0 [2] 86 fe [2] bb }

  condition:
    any of them
}