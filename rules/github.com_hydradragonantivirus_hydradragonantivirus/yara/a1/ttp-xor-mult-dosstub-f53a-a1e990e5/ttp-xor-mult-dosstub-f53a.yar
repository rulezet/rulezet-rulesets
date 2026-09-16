rule TTP_XOR_MULT_DOSStub_f53a {
  strings:
    $key_f53a = { a1 52 [2] d5 4a [2] 92 48 [2] d5 59 [2] 9b 55 [2] 97 5f [2] 80 54 [2] 9b 1a [2] a6 }

  condition:
    any of them
}