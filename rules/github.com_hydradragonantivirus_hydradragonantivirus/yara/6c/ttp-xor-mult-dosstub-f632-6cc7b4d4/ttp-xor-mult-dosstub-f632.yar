rule TTP_XOR_MULT_DOSStub_f632 {
  strings:
    $key_f632 = { a2 5a [2] d6 42 [2] 91 40 [2] d6 51 [2] 98 5d [2] 94 57 [2] 83 5c [2] 98 12 [2] a5 }

  condition:
    any of them
}