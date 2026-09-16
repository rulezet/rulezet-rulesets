rule TTP_XOR_MULT_DOSStub_f22a {
  strings:
    $key_f22a = { a6 42 [2] d2 5a [2] 95 58 [2] d2 49 [2] 9c 45 [2] 90 4f [2] 87 44 [2] 9c 0a [2] a1 }

  condition:
    any of them
}