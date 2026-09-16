rule TTP_XOR_MULT_DOSStub_f3e8 {
  strings:
    $key_f3e8 = { a7 80 [2] d3 98 [2] 94 9a [2] d3 8b [2] 9d 87 [2] 91 8d [2] 86 86 [2] 9d c8 [2] a0 }

  condition:
    any of them
}