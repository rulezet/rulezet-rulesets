rule TTP_XOR_MULT_DOSStub_f17a {
  strings:
    $key_f17a = { a5 12 [2] d1 0a [2] 96 08 [2] d1 19 [2] 9f 15 [2] 93 1f [2] 84 14 [2] 9f 5a [2] a2 }

  condition:
    any of them
}