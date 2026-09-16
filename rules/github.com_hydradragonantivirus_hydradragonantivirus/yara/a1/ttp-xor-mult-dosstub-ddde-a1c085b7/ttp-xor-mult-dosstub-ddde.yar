rule TTP_XOR_MULT_DOSStub_ddde {
  strings:
    $key_ddde = { 89 b6 [2] fd ae [2] ba ac [2] fd bd [2] b3 b1 [2] bf bb [2] a8 b0 [2] b3 fe [2] 8e }

  condition:
    any of them
}