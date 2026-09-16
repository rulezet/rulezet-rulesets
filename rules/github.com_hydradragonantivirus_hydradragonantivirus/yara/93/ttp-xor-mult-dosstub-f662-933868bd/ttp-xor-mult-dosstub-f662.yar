rule TTP_XOR_MULT_DOSStub_f662 {
  strings:
    $key_f662 = { a2 0a [2] d6 12 [2] 91 10 [2] d6 01 [2] 98 0d [2] 94 07 [2] 83 0c [2] 98 42 [2] a5 }

  condition:
    any of them
}