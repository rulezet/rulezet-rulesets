rule TTP_XOR_MULT_DOSStub_f63f {
  strings:
    $key_f63f = { a2 57 [2] d6 4f [2] 91 4d [2] d6 5c [2] 98 50 [2] 94 5a [2] 83 51 [2] 98 1f [2] a5 }

  condition:
    any of them
}