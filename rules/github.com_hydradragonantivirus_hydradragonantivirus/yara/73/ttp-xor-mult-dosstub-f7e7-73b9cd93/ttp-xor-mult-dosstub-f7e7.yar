rule TTP_XOR_MULT_DOSStub_f7e7 {
  strings:
    $key_f7e7 = { a3 8f [2] d7 97 [2] 90 95 [2] d7 84 [2] 99 88 [2] 95 82 [2] 82 89 [2] 99 c7 [2] a4 }

  condition:
    any of them
}