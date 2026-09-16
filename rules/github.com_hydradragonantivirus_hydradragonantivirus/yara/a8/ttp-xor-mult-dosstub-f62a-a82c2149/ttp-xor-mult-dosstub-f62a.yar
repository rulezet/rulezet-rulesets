rule TTP_XOR_MULT_DOSStub_f62a {
  strings:
    $key_f62a = { a2 42 [2] d6 5a [2] 91 58 [2] d6 49 [2] 98 45 [2] 94 4f [2] 83 44 [2] 98 0a [2] a5 }

  condition:
    any of them
}