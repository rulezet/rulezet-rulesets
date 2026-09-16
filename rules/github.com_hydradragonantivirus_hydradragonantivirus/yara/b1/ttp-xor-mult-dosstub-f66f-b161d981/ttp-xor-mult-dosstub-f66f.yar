rule TTP_XOR_MULT_DOSStub_f66f {
  strings:
    $key_f66f = { a2 07 [2] d6 1f [2] 91 1d [2] d6 0c [2] 98 00 [2] 94 0a [2] 83 01 [2] 98 4f [2] a5 }

  condition:
    any of them
}