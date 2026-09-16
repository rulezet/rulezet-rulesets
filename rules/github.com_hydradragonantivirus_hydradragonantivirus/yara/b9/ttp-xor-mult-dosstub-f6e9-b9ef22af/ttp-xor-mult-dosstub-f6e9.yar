rule TTP_XOR_MULT_DOSStub_f6e9 {
  strings:
    $key_f6e9 = { a2 81 [2] d6 99 [2] 91 9b [2] d6 8a [2] 98 86 [2] 94 8c [2] 83 87 [2] 98 c9 [2] a5 }

  condition:
    any of them
}