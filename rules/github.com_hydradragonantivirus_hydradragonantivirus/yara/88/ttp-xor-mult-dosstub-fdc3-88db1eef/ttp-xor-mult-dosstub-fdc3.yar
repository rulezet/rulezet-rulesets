rule TTP_XOR_MULT_DOSStub_fdc3 {
  strings:
    $key_fdc3 = { a9 ab [2] dd b3 [2] 9a b1 [2] dd a0 [2] 93 ac [2] 9f a6 [2] 88 ad [2] 93 e3 [2] ae }

  condition:
    any of them
}