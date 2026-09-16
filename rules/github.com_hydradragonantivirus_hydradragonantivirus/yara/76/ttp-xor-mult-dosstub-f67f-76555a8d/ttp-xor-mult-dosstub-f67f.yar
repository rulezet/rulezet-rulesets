rule TTP_XOR_MULT_DOSStub_f67f {
  strings:
    $key_f67f = { a2 17 [2] d6 0f [2] 91 0d [2] d6 1c [2] 98 10 [2] 94 1a [2] 83 11 [2] 98 5f [2] a5 }

  condition:
    any of them
}