rule TTP_XOR_MULT_DOSStub_f609 {
  strings:
    $key_f609 = { a2 61 [2] d6 79 [2] 91 7b [2] d6 6a [2] 98 66 [2] 94 6c [2] 83 67 [2] 98 29 [2] a5 }

  condition:
    any of them
}