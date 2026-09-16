rule TTP_XOR_MULT_DOSStub_f309 {
  strings:
    $key_f309 = { a7 61 [2] d3 79 [2] 94 7b [2] d3 6a [2] 9d 66 [2] 91 6c [2] 86 67 [2] 9d 29 [2] a0 }

  condition:
    any of them
}