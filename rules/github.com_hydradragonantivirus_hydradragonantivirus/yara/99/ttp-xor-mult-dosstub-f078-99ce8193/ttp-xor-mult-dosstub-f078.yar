rule TTP_XOR_MULT_DOSStub_f078 {
  strings:
    $key_f078 = { a4 10 [2] d0 08 [2] 97 0a [2] d0 1b [2] 9e 17 [2] 92 1d [2] 85 16 [2] 9e 58 [2] a3 }

  condition:
    any of them
}