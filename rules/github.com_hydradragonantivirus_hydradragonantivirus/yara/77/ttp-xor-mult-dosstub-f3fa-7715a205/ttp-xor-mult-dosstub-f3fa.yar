rule TTP_XOR_MULT_DOSStub_f3fa {
  strings:
    $key_f3fa = { a7 92 [2] d3 8a [2] 94 88 [2] d3 99 [2] 9d 95 [2] 91 9f [2] 86 94 [2] 9d da [2] a0 }

  condition:
    any of them
}