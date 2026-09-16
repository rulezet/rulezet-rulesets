rule TTP_XOR_MULT_DOSStub_f65a {
  strings:
    $key_f65a = { a2 32 [2] d6 2a [2] 91 28 [2] d6 39 [2] 98 35 [2] 94 3f [2] 83 34 [2] 98 7a [2] a5 }

  condition:
    any of them
}