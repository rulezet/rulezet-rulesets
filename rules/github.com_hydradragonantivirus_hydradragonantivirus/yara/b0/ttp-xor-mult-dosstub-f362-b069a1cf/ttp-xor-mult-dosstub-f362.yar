rule TTP_XOR_MULT_DOSStub_f362 {
  strings:
    $key_f362 = { a7 0a [2] d3 12 [2] 94 10 [2] d3 01 [2] 9d 0d [2] 91 07 [2] 86 0c [2] 9d 42 [2] a0 }

  condition:
    any of them
}