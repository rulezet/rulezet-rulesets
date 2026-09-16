rule TTP_XOR_MULT_DOSStub_f539 {
  strings:
    $key_f539 = { a1 51 [2] d5 49 [2] 92 4b [2] d5 5a [2] 9b 56 [2] 97 5c [2] 80 57 [2] 9b 19 [2] a6 }

  condition:
    any of them
}