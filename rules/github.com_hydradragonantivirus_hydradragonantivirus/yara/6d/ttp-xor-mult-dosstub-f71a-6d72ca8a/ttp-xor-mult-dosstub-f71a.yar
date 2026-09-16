rule TTP_XOR_MULT_DOSStub_f71a {
  strings:
    $key_f71a = { a3 72 [2] d7 6a [2] 90 68 [2] d7 79 [2] 99 75 [2] 95 7f [2] 82 74 [2] 99 3a [2] a4 }

  condition:
    any of them
}