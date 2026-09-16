rule TTP_XOR_MULT_DOSStub_f23f {
  strings:
    $key_f23f = { a6 57 [2] d2 4f [2] 95 4d [2] d2 5c [2] 9c 50 [2] 90 5a [2] 87 51 [2] 9c 1f [2] a1 }

  condition:
    any of them
}