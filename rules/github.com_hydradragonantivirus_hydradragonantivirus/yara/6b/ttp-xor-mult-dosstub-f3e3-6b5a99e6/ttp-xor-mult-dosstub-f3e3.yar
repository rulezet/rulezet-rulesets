rule TTP_XOR_MULT_DOSStub_f3e3 {
  strings:
    $key_f3e3 = { a7 8b [2] d3 93 [2] 94 91 [2] d3 80 [2] 9d 8c [2] 91 86 [2] 86 8d [2] 9d c3 [2] a0 }

  condition:
    any of them
}