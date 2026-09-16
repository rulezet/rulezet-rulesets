rule TTP_XOR_MULT_DOSStub_f77f {
  strings:
    $key_f77f = { a3 17 [2] d7 0f [2] 90 0d [2] d7 1c [2] 99 10 [2] 95 1a [2] 82 11 [2] 99 5f [2] a4 }

  condition:
    any of them
}