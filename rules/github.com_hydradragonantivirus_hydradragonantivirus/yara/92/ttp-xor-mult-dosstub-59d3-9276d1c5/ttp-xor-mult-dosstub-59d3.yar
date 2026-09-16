rule TTP_XOR_MULT_DOSStub_59d3 {
  strings:
    $key_59d3 = { 0d bb [2] 79 a3 [2] 3e a1 [2] 79 b0 [2] 37 bc [2] 3b b6 [2] 2c bd [2] 37 f3 [2] 0a }

  condition:
    any of them
}