rule TTP_XOR_MULT_DOSStub_f3fc {
  strings:
    $key_f3fc = { a7 94 [2] d3 8c [2] 94 8e [2] d3 9f [2] 9d 93 [2] 91 99 [2] 86 92 [2] 9d dc [2] a0 }

  condition:
    any of them
}