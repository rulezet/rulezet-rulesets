rule TTP_XOR_MULT_DOSStub_f075 {
  strings:
    $key_f075 = { a4 1d [2] d0 05 [2] 97 07 [2] d0 16 [2] 9e 1a [2] 92 10 [2] 85 1b [2] 9e 55 [2] a3 }

  condition:
    any of them
}