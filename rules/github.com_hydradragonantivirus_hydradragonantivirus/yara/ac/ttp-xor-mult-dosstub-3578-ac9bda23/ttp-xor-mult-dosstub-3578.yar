rule TTP_XOR_MULT_DOSStub_3578 {
  strings:
    $key_3578 = { 61 10 [2] 15 08 [2] 52 0a [2] 15 1b [2] 5b 17 [2] 57 1d [2] 40 16 [2] 5b 58 [2] 66 }

  condition:
    any of them
}