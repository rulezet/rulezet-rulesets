rule TTP_XOR_MULT_DOSStub_f35b {
  strings:
    $key_f35b = { a7 33 [2] d3 2b [2] 94 29 [2] d3 38 [2] 9d 34 [2] 91 3e [2] 86 35 [2] 9d 7b [2] a0 }

  condition:
    any of them
}